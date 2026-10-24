#!/usr/bin/env python3
"""Remote pre-dumps and a local final dump of private COW and shared pages."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
from socket import AF_INET, SOCK_STREAM, socket as Socket
import subprocess
import struct
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'lib'))


def run(command, logfile, env=None):
    with logfile.open('w') as output:
        subprocess.run([str(s) for s in command], check=True, timeout=90,
                       stdout=output, stderr=subprocess.STDOUT, env=env)


def wait_until(predicate, message, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise RuntimeError(message)


def alive(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1][0] != 'Z'
    except FileNotFoundError:
        return False


def memory(pid, address, expected=None, value=None):
    with open(f'/proc/{pid}/mem', 'r+b', buffering=0) as fd:
        if expected is not None:
            actual = os.pread(fd.fileno(), len(expected), address)
            if actual != expected:
                raise RuntimeError(f'byte mismatch pid={pid} address={address:#x}')
        if value is not None:
            if os.pwrite(fd.fileno(), value, address) != len(value):
                raise RuntimeError('short workload memory write')


def image_entries(directory, pid):
    import pycriu.images
    with (directory / f'pagemap-{pid}.img').open('rb') as image:
        return pycriu.images.load(image)['entries'][1:]


def page_flags(directory, pid, address, page_size):
    selected = [entry for entry in image_entries(directory, pid)
                if int(entry['vaddr']) <= address < int(entry['vaddr']) +
                int(entry['nr_pages']) * page_size]
    if len(selected) != 1:
        raise RuntimeError(f'no unique pagemap entry for {pid}/{address:#x}')
    return int(selected[0].get('flags', 0)) & 5


def dirty_private_pages(pid, address, length, page_size):
    count = length // page_size
    with open(f'/proc/{pid}/pagemap', 'rb', buffering=0) as image:
        data = os.pread(image.fileno(), count * 8, address // page_size * 8)
    if len(data) != count * 8:
        raise RuntimeError('short pagemap read from test workload')
    return [index for index, (entry,) in enumerate(struct.iter_unpack('=Q', data))
            if entry & (1 << 55)]


def private_huge_kb(smaps, address, length):
    """Return a lower bound in kB for anonymous huge pages in the tested range."""
    huge_kb = 0
    outside = None
    for line in smaps.splitlines():
        mapping = re.match(r'^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+', line)
        if mapping:
            start, end = (int(value, 16) for value in mapping.group(1, 2))
            overlap = max(0, min(end, address + length) - max(start, address))
            outside = end - start - overlap if overlap and mapping[3].endswith('p') else None
        elif outside is not None and line.startswith('AnonHugePages:'):
            # smaps counters cover the entire VMA. If it extends beyond the
            # workload, discount all outside bytes to avoid attributing an
            # unrelated huge page to the tested private range.
            huge_kb += max(0, int(line.split()[1]) * 1024 - outside) // 1024
    return huge_kb


def thp_snapshot(capture, pids, address, length):
    return {'capture': capture, 'processes': [
        {'pid': pid, 'private_huge_kb': private_huge_kb(
            Path(f'/proc/{pid}/smaps').read_text(), address, length)}
        for pid in pids]}


def thp_status(requested, snapshots):
    if not requested:
        return 'NOT_REQUESTED'
    # Require huge pages in both processes before each capture, including
    # after COW writes.
    exercised = len(snapshots) == 3 and all(
        len(snapshot['processes']) == 2 and all(
            process['private_huge_kb'] > 0 for process in snapshot['processes'])
        for snapshot in snapshots)
    return 'PASS' if exercised else 'SKIP'


def verify_dirty_capture(directory, pid, address, length, page_size, dirty):
    flags = [None] * (length // page_size)
    for entry in image_entries(directory, pid):
        lo = max(address, int(entry['vaddr']))
        hi = min(address + length, int(entry['vaddr']) + int(entry['nr_pages']) * page_size)
        for current in range(lo, hi, page_size):
            flags[(current - address) // page_size] = int(entry.get('flags', 0)) & 5
    if any(value not in (1, 4) for value in flags):
        raise RuntimeError('private mapping has missing or invalid page coverage')
    if any(flags[index] != 4 for index in dirty):
        raise RuntimeError('a page observed soft-dirty was incorrectly inherited')
    return {'pid': pid, 'softdirty_before': len(dirty),
            'present_pages': flags.count(4), 'parent_pages': flags.count(1)}


def case(work, executable, mode, compressed=False, thp=False, dedup=False):
    label = f'{mode}-{"compressed" if compressed else "plain"}'
    label += '-thp' if thp else '-base'
    label += '-dedup' if dedup else ''
    base = work / label
    base.mkdir()
    manifest = base / 'workload.txt'
    environment = os.environ.copy()
    # Cover the default conservative path with shmem tracking disabled.
    environment.pop('CRIU_TRACK_SHMEM', None)
    if thp:
        environment['CRIU_TEST_THP'] = '1'
    else:
        environment.pop('CRIU_TEST_THP', None)
    pids = []
    server = None
    process = None
    criu = [str(ROOT / 'criu/criu'), '--no-default-config']
    # Deliberately client/final-only: receiver auto-dedup modifies older
    # destination payloads and is not covered by source metadata rollback.
    extras = (['--compress'] if compressed else []) + (['--auto-dedup'] if dedup else [])
    with (base / 'workload.log').open('w') as log:
        try:
            process = subprocess.Popen([str(executable), str(manifest)], stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=log, start_new_session=True, env=environment)
            wait_until(lambda: manifest.exists() and len(manifest.read_text().split()) == 7,
                       'workload startup failed')
            parent, child, private, shared, private_size, shared_size, page_size = map(
                int, manifest.read_text().split())
            pids = [parent, child]
            if process.pid != parent:
                raise RuntimeError('unexpected workload identity')
            payloads = []
            dirty_evidence = []
            thp_evidence = []
            for iteration in (1, 2):
                source = base / f'source-{iteration}'
                target = base / f'target-{iteration}'
                source.mkdir()
                target.mkdir()
                observed_dirty = {pid: dirty_private_pages(pid, private, private_size, page_size)
                                  for pid in pids}
                # Keep the listener bound until CRIU gets the accepted socket
                # through --ps-socket.
                with Socket(AF_INET, SOCK_STREAM) as listener:
                    listener.bind(('127.0.0.1', 0))
                    listener.listen(1)
                    listener.settimeout(20)
                    command = criu + ['pre-dump', '-t', str(parent), '-D', str(source),
                                      '-o', 'dump.log', '-v4', '--track-mem', '--pre-dump-mode', mode,
                                      '--page-server', '--address', '127.0.0.1', '--port',
                                      str(listener.getsockname()[1])] + extras
                    if iteration == 2:
                        command += ['--prev-images-dir', '../source-1']
                    with (base / f'client-{iteration}.log').open('w') as client_log:
                        if thp:
                            thp_evidence.append(thp_snapshot(f'pre-dump-{iteration}', pids,
                                                             private, private_size))
                        client = subprocess.Popen(command, stdout=client_log, stderr=client_log, env=environment)
                        try:
                            connection, _ = listener.accept()
                            with connection:
                                server_command = criu + ['page-server', '-D', str(target), '-o', 'server.log',
                                                         '-v4', '--ps-socket', str(connection.fileno())]
                                if iteration == 2:
                                    server_command += ['--prev-images-dir', '../target-1']
                                with (base / f'server-{iteration}.log').open('w') as server_log:
                                    server = subprocess.Popen(server_command, pass_fds=[connection.fileno()],
                                                              stdout=server_log, stderr=server_log, env=environment)
                                if client.wait(timeout=60) or server.wait(timeout=60):
                                    raise RuntimeError('pre-dump/page-server failed')
                                server = None
                        finally:
                            if client.poll() is None:
                                client.kill()
                                client.wait()
                if any(source.glob('pages-*.img')):
                    raise RuntimeError('source retained page payload')
                if len(list(source.glob('pagemap-*.img'))) != 2:
                    raise RuntimeError('coverage missing for one of the two processes')
                # On this path anonymous shared mappings are represented as
                # memfd-backed FILE_SHARED VMAs. Stock pre-dump defers them to
                # the final dump; remote coverage does not track shared-page
                # dirtiness. Check final capture and sharing below.
                if list(source.glob('.pagemap-*.img.tmp.*')):
                    raise RuntimeError('temporary coverage remained')
                payloads.append(sum(p.stat().st_size for p in target.glob('pages-*.img')))
                captured = [verify_dirty_capture(target, pid, private, private_size,
                                                 page_size, observed_dirty[pid]) for pid in pids]
                dirty_evidence.append({'iteration': iteration, 'processes': captured})
                (base / 'dirty-capture.json').write_text(json.dumps(dirty_evidence, indent=2) + '\n')
                memory(child if iteration == 1 else parent, shared + (iteration - 1) * page_size,
                       value=bytes([0x31 if iteration == 1 else 0x72]) * page_size)
                memory(child if iteration == 1 else parent, private + (iteration - 1) * page_size,
                       value=bytes([0xCC if iteration == 1 else 0xDD]) * page_size)
            final = base / 'final'
            final.mkdir()
            final_dirty = {pid: dirty_private_pages(pid, private, private_size, page_size) for pid in pids}
            if thp:
                thp_evidence.append(thp_snapshot('final-dump', pids, private, private_size))
            run(criu + ['dump', '-t', str(parent), '-D', str(final), '-o', 'dump.log', '-v4',
                        '--track-mem', '--prev-images-dir', '../source-2'] + extras,
                base / 'final-command.log', environment)
            process.wait(timeout=10)
            # Check whether shared pages were pre-dumped or deferred as memfd.
            import pycriu.images
            with (final / f'mm-{parent}.img').open('rb') as image:
                mm = pycriu.images.load(image)['entries'][0]
            mapping = [vma for vma in mm['vmas']
                       if int(vma['start']) <= shared < int(vma['end'])]
            if len(mapping) != 1 or not int(mapping[0]['flags']) & 1:
                raise RuntimeError('shared mapping metadata was not preserved')
            shared_counts = [len(list((base / f'source-{i}').glob('pagemap-shmem-*.img')))
                             for i in (1, 2)]
            memfd_backed = bool(int(mapping[0]['status']) & (1 << 14))
            if not any(shared_counts) and not memfd_backed:
                raise RuntimeError('shared pre-dump coverage missing without memfd deferral')
            shared_strategy = 'memfd-final-capture' if not any(shared_counts) else 'predump-coverage'
            final_payload = sum(p.stat().st_size for p in final.glob('pages-*.img'))
            final_capture = [verify_dirty_capture(final, pid, private, private_size, page_size,
                                                  final_dirty[pid]) for pid in pids]
            if not any(item['parent_pages'] for item in final_capture):
                raise RuntimeError('final dump lost all private parent inheritance')
            # Private generation A must come through the latest parent chain;
            # generation B must be in the current image. THP can recopy neighbors.
            if not thp and (page_flags(final, child, private, page_size) != 1 or
                            page_flags(final, parent, private + page_size, page_size) != 4):
                raise RuntimeError('private generation placement is incorrect')
            # THP/COW can dirty whole PMDs, so apply size limits only to base
            # pages. Dirty-page capture and restored bytes are checked for both.
            if not compressed and not thp and (payloads[1] * 4 >= payloads[0] or final_payload * 4 >= payloads[0]):
                raise RuntimeError('private memory did not remain incremental')
            (final / 'parent').unlink()
            (final / 'parent').symlink_to('../target-2')
            run(criu + ['restore', '-D', str(final), '-o', 'restore.log', '-v4', '-d'],
                base / 'restore-command.log', environment)
            if not all(alive(pid) for pid in pids):
                raise RuntimeError('restored process missing')
            shared_expected = bytearray([0x19]) * shared_size
            shared_expected[:page_size] = bytes([0x31]) * page_size
            shared_expected[page_size:2 * page_size] = bytes([0x72]) * page_size
            for pid in pids:
                expected = bytearray([0x29]) * private_size
                index = 0 if pid == child else 1
                expected[index * page_size:(index + 1) * page_size] = bytes([0xCC if pid == child else 0xDD]) * page_size
                memory(pid, private, bytes(expected))
                memory(pid, shared, bytes(shared_expected))
            memory(child, shared + 3 * page_size, value=b'Z')
            memory(parent, shared + 3 * page_size, expected=b'Z')
            huge_status = thp_status(thp, thp_evidence)
            result = {'case': label, 'status': 'SKIP' if huge_status == 'SKIP' else 'PASS',
                      'bytes_status': 'PASS', 'thp_status': huge_status, 'pre_payloads': payloads,
                      'final_payload': final_payload, 'private_bytes_checked': private_size * 2,
                      'shared_bytes_checked': shared_size * 2, 'thp_evidence': thp_evidence,
                      'thp_exercised': huge_status == 'PASS', 'restored_sharing_verified': True,
                      'shared_strategy': shared_strategy,
                      'dedup_scope': 'client-final-only' if dedup else 'disabled',
                      'shared_predump_coverage_counts': shared_counts,
                      'dirty_capture': dirty_evidence, 'final_capture': final_capture,
                      'predump_payload_ratio': payloads[1] / payloads[0],
                      'final_payload_ratio': final_payload / payloads[0]}
            (base / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result), flush=True)
            if huge_status == 'SKIP':
                print(f'SKIP: {label}: THP not proven in both tested private mappings at every capture; '
                      'restored bytes and sharing PASS', flush=True)
            return result
        finally:
            if server is not None and server.poll() is None:
                server.kill()
                server.wait()
            for pid in reversed(pids):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    continue
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-thp', action='store_true',
                        help='fail unless THP is observed in both private mappings before every capture')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('run this regression as root on an isolated CRIU test host')
    work = Path(tempfile.mkdtemp(prefix='shared-regression.', dir=HERE))
    print(f'Work directory: {work}', flush=True)
    executable = work / 'workload'
    run([os.environ.get('CC', 'cc'), '-O2', '-Wall', '-Wextra', '-Werror',
         HERE / 'shared_workload.c', '-o', executable], work / 'compile.log')
    with (work / 'compression-feature.log').open('w') as log:
        compression = subprocess.run([str(ROOT / 'criu/criu'), '--no-default-config',
                                      'check', '--feature', 'compress'], stdout=log,
                                     stderr=subprocess.STDOUT, timeout=30).returncode == 0
    if not compression:
        print('SKIP: compressed variants unavailable; plain shared-memory cases still run', flush=True)
    results = []
    for mode in ('splice', 'read'):
        for compressed in ((False, True) if compression else (False,)):
            results.append(case(work, executable, mode, compressed))
    results.append(case(work, executable, 'read', thp=True))
    results.append(case(work, executable, 'splice', dedup=True))
    (work / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    if any(result['thp_status'] == 'SKIP' for result in results):
        if args.require_thp:
            raise RuntimeError('required THP coverage was not observed; see results.json')
        print('SHARED-REGRESSION BYTES PASSED; THP SKIPPED', flush=True)
    else:
        print('SHARED-REGRESSION PASSED', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
