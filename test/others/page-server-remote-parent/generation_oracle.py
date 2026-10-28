#!/usr/bin/env python3
"""External page-generation oracle for the remote-parent regression.

Expected bytes are retained outside the checkpointed task. Mutations remain in
place until *after* the complete 33 MiB patterned workload range has been
verified, then are undone so the unchanged compress_pages00 workload can
verify its other memory as well.
"""
import argparse
import json
import os
from pathlib import Path
import sys

PE_PARENT = 1
PE_PRESENT = 4
# Match NR_COMP_PAGES in compress_pages00.c, including the read batch boundary.
PATTERN_BYTES = 33 << 20


def entries(directory, pid):
    import pycriu.images
    with (Path(directory) / f'pagemap-{pid}.img').open('rb') as image:
        return pycriu.images.load(image)['entries'][1:]


def read_exact(fd, address, size):
    data = os.pread(fd, size, address)
    if len(data) != size:
        raise RuntimeError(f'Short memory read at {address:#x}: {len(data)}/{size}')
    return data


def write_exact(fd, address, data):
    if os.pwrite(fd, data, address) != len(data):
        raise RuntimeError(f'Short memory write at {address:#x}')


def save(path, state):
    # The directory belongs exclusively to this regression invocation.
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('x') as output:
        json.dump(state, output, indent=2)
        output.write('\n')
    temporary.replace(path)


def initial_state(fd, image_entries, size):
    # A single mapping may be split into several pagemap entries by the
    # 32 MiB transfer batch. Merge adjacent payload ranges before locating
    # the workload, rather than checking just the largest individual entry.
    ranges = []
    for entry in sorted(image_entries, key=lambda e: int(e['vaddr'])):
        if not int(entry.get('flags', 0)) & PE_PRESENT:
            continue
        start = int(entry['vaddr'])
        end = start + int(entry['nr_pages']) * size
        if ranges and ranges[-1][1] == start:
            ranges[-1][1] = end
        else:
            ranges.append([start, end])
    pattern = bytes(range(256))
    expected = pattern * (PATTERN_BYTES // len(pattern))
    for start, end in ranges:
        if end - start < PATTERN_BYTES:
            continue
        offset = read_exact(fd, start, end - start).find(expected)
        if offset >= 0 and offset % size == 0:
            address = start + offset
            break
    else:
        raise RuntimeError('Cannot identify the complete 33 MiB patterned workload')
    # Generation B is beyond the first 32 MiB batch; the middle page stays
    # untouched and must resolve all the way through the image chain.
    offsets = (4 * size, (32 << 20) + 4 * size, 16 << 20)
    pages = []
    original = (pattern * (size // len(pattern))).hex()
    for offset in offsets:
        pages.append({'address': address + offset, 'original': original,
                      'expected': original, 'generation': 0})
    return {'page_size': size, 'mutations': 0, 'pages': pages,
            'range': {'address': address, 'length': PATTERN_BYTES,
                      'pattern': pattern.hex()}}


def mutate_page(fd, state):
    index = state['mutations']
    if index not in (0, 1):
        raise RuntimeError('Only two mutation generations are supported')
    page = state['pages'][index]
    expected = bytes.fromhex(page['expected'])
    if read_exact(fd, page['address'], len(expected)) != expected:
        raise RuntimeError('Workload changed a page reserved for the oracle')
    changed = bytes(value ^ (0x55 if index == 0 else 0xAA) for value in expected)
    write_exact(fd, page['address'], changed)
    page['expected'] = changed.hex()
    page['generation'] = index + 1
    state['mutations'] += 1
    print(f'GENERATION: changed page {index}, generation {index + 1}')


def mutate(directory, pid, state_path):
    state_path = Path(state_path)
    with open(f'/proc/{pid}/mem', 'r+b', buffering=0) as memory:
        fd = memory.fileno()
        if state_path.exists():
            state = json.loads(state_path.read_text())
        else:
            state = initial_state(fd, entries(directory, pid),
                                  os.sysconf('SC_PAGE_SIZE'))
        mutate_page(fd, state)
        save(state_path, state)


def check_entries(image_entries, state, full=False):
    # A full retry has no parent. Otherwise only the latest mutation belongs
    # in this image; earlier generations and the control resolve via parent.
    latest = state['mutations'] - 1
    size = state['page_size']
    for index, page in enumerate(state['pages']):
        address = page['address']
        found = [e for e in image_entries
                 if int(e['vaddr']) <= address
                 and int(e['vaddr']) + int(e['nr_pages']) * size >= address + size]
        if len(found) != 1:
            raise RuntimeError(f'Expected one pagemap entry for {address:#x}')
        flags = int(found[0].get('flags', 0)) & (PE_PARENT | PE_PRESENT)
        wanted = PE_PRESENT if full or index == latest else PE_PARENT
        if flags != wanted:
            raise RuntimeError(f'Page {index}: flags {flags}, expected {wanted}')
    print('GENERATION: current payload and parent-reference placement verified')


def check_image(directory, pid, state_path, full=False):
    check_entries(entries(directory, pid), json.loads(Path(state_path).read_text()), full)


def verify_memory(fd, state):
    region = state['range']
    size = state['page_size']
    pattern = bytes.fromhex(region['pattern'])
    unchanged = pattern * (size // len(pattern))
    changed = {page['address']: bytes.fromhex(page['expected'])
               for page in state['pages']}
    # Check every byte of the full workload range, including pages that were
    # never selected for mutation, before resetting modified bytes.
    for address in range(region['address'], region['address'] + region['length'], size):
        expected = changed.get(address, unchanged)
        actual = read_exact(fd, address, size)
        if actual != expected:
            raise RuntimeError(f'Restored page at {address:#x} is stale or corrupted')
    print(f'GENERATION: all {region["length"]} restored bytes match external expectations')


def verify_and_reset(pid, state_path):
    state = json.loads(Path(state_path).read_text())
    with open(f'/proc/{pid}/mem', 'r+b', buffering=0) as memory:
        fd = memory.fileno()
        verify_memory(fd, state)
        for page in state['pages']:
            if page['generation']:
                write_exact(fd, page['address'], bytes.fromhex(page['original']))


def self_test():
    # No CRIU images, protobuf bindings, root, or other-process access needed.
    import ctypes
    import mmap
    import tempfile

    size = os.sysconf('SC_PAGE_SIZE')
    pattern = bytes(range(256))
    original = pattern * (PATTERN_BYTES // len(pattern))
    with mmap.mmap(-1, PATTERN_BYTES) as mapping, tempfile.TemporaryDirectory() as directory:
        mapping[:] = original
        address = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
        image_entries = [
            {'vaddr': address, 'nr_pages': (32 << 20) // size, 'flags': PE_PRESENT},
            {'vaddr': address + (32 << 20), 'nr_pages': (1 << 20) // size, 'flags': PE_PRESENT},
        ]
        with open('/proc/self/mem', 'r+b', buffering=0) as memory:
            fd = memory.fileno()
            state = initial_state(fd, image_entries, size)
            mutate_page(fd, state)
            mutate_page(fd, state)
        state_path = Path(directory) / 'state.json'
        save(state_path, state)
        placement = [{'vaddr': page['address'], 'nr_pages': 1,
                      'flags': PE_PRESENT if index == 1 else PE_PARENT}
                     for index, page in enumerate(state['pages'])]
        check_entries(placement, state)
        full = [dict(entry, flags=PE_PRESENT) for entry in placement]
        check_entries(full, state, full=True)
        placement[0]['flags'] = PE_PRESENT
        try:
            check_entries(placement, state)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('Incorrect generation placement was accepted')

        # Corrupt an unselected page in the last batch. A failing verification
        # must leave both mutation generations unchanged, never repairing them.
        damaged = (32 << 20) + 8 * size
        mapping[damaged] ^= 0xFF
        try:
            verify_and_reset(os.getpid(), state_path)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('Corruption outside selected pages was accepted')
        for page in state['pages'][:2]:
            offset = page['address'] - address
            if mapping[offset:offset + size] != bytes.fromhex(page['expected']):
                raise RuntimeError('Failed verification repaired a mutation')
        mapping[damaged] ^= 0xFF

        # A stale inherited generation must also be rejected before resetting.
        first = state['pages'][0]['address'] - address
        saved = mapping[first:first + size]
        mapping[first:first + size] = bytes.fromhex(state['pages'][0]['original'])
        try:
            verify_and_reset(os.getpid(), state_path)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('Stale generation was accepted')
        second = state['pages'][1]['address'] - address
        if mapping[second:second + size] != bytes.fromhex(state['pages'][1]['expected']):
            raise RuntimeError('Stale-generation verification repaired a mutation')
        mapping[first:first + size] = saved
        verify_and_reset(os.getpid(), state_path)
        if mapping[:] != original:
            raise RuntimeError('Successful verification did not restore original bytes')
    print('GENERATION: self-test passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('self-test')
    for command in ('mutate', 'check-image'):
        p = sub.add_parser(command)
        p.add_argument('directory')
        p.add_argument('pid', type=int)
        p.add_argument('state_path')
        if command == 'check-image':
            p.add_argument('--full', action='store_true',
                           help='require all selected pages in a full retry image')
    p = sub.add_parser('verify-and-reset')
    p.add_argument('pid', type=int)
    p.add_argument('state_path')
    args = parser.parse_args()
    if args.command == 'self-test':
        self_test()
    elif args.command == 'mutate':
        mutate(args.directory, args.pid, args.state_path)
    elif args.command == 'check-image':
        check_image(args.directory, args.pid, args.state_path, args.full)
    else:
        verify_and_reset(args.pid, args.state_path)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
