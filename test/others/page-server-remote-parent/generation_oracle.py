#!/usr/bin/env python3
"""External page-generation oracle for the remote-parent regression.

Expected bytes are retained outside the checkpointed task. Mutations remain in
place until *after* restored bytes have been verified, then are undone so the
unchanged compress_pages00 workload can verify all its other memory as well.
"""
import argparse
import json
import os
from pathlib import Path
import sys

PE_PARENT = 1
PE_PRESENT = 4


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


def mutate(directory, pid, state_path):
    state_path = Path(state_path)
    with open(f'/proc/{pid}/mem', 'r+b', buffering=0) as memory:
        fd = memory.fileno()
        if state_path.exists():
            state = json.loads(state_path.read_text())
        else:
            size = os.sysconf('SC_PAGE_SIZE')
            present = [e for e in entries(directory, pid)
                       if int(e.get('flags', 0)) & PE_PRESENT]
            if not present:
                raise RuntimeError('No present range for generation test')
            chosen = max(present, key=lambda e: int(e.get('nr_pages', 0)))
            if int(chosen.get('nr_pages', 0)) < 16:
                raise RuntimeError('Workload has no sufficiently large range')
            # Skip the boundary of the largest (33 MiB patterned) workload range.
            address = int(chosen['vaddr']) + 4 * size
            pages = []
            for offset in range(3):
                base = address + offset * size
                original = read_exact(fd, base, size).hex()
                pages.append({'address': base, 'original': original,
                              'expected': original, 'generation': 0})
            state = {'page_size': size, 'mutations': 0, 'pages': pages}
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
        save(state_path, state)
        print(f'GENERATION: changed page {index}, generation {index + 1}')


def check_entries(image_entries, state):
    # Only the latest mutation belongs in the current image; the previous
    # generation and untouched control must resolve through its parent.
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
        wanted = PE_PRESENT if index == latest else PE_PARENT
        if flags != wanted:
            raise RuntimeError(f'Page {index}: flags {flags}, expected {wanted}')
    print('GENERATION: current payload and parent-reference placement verified')


def check_image(directory, pid, state_path):
    check_entries(entries(directory, pid), json.loads(Path(state_path).read_text()))


def verify_and_reset(pid, state_path):
    state = json.loads(Path(state_path).read_text())
    with open(f'/proc/{pid}/mem', 'r+b', buffering=0) as memory:
        fd = memory.fileno()
        # Verify EVERY selected page before modifying ANY restored byte.
        for index, page in enumerate(state['pages']):
            expected = bytes.fromhex(page['expected'])
            actual = read_exact(fd, page['address'], len(expected))
            if actual != expected:
                raise RuntimeError(f'Restored page {index} is stale or corrupted; '
                                   f'expected generation {page["generation"]}')
        print('GENERATION: all restored pages match external expected bytes')
        for page in state['pages']:
            if page['generation']:
                write_exact(fd, page['address'], bytes.fromhex(page['original']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('mutate', 'check-image'):
        p = sub.add_parser(command)
        p.add_argument('directory')
        p.add_argument('pid', type=int)
        p.add_argument('state_path')
    p = sub.add_parser('verify-and-reset')
    p.add_argument('pid', type=int)
    p.add_argument('state_path')
    args = parser.parse_args()
    if args.command == 'mutate':
        mutate(args.directory, args.pid, args.state_path)
    elif args.command == 'check-image':
        check_image(args.directory, args.pid, args.state_path)
    else:
        verify_and_reset(args.pid, args.state_path)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
