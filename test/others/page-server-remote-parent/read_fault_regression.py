#!/usr/bin/env python3
"""Deterministic read-pre-dump faults, exact coverage, and restored-byte checks."""
import json
import os
from pathlib import Path
import re
import signal
from socket import AF_INET, SOCK_STREAM, socket as Socket
import subprocess
import sys
import tempfile

from shared_regression import HERE, ROOT, alive, image_entries, memory, page_flags, run, wait_until


SUCCESS_CASES = ('short-read', 'first-efault', 'partial-efault', 'recovery-esrch')
ERROR_CASES = ('recovery-eperm', 'zero-read', 'recovery-zero', 'vmsplice-error', 'vmsplice-short')


def remote_predump(base, name, parent, environment):
    source, target = base / f'{name}-source', base / f'{name}-target'
    source.mkdir()
    target.mkdir()
    criu = [str(ROOT / 'criu/criu'), '--no-default-config']
    client = server = None
    with Socket(AF_INET, SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(20)
        with (base / f'{name}-client.log').open('w') as client_log, \
                (base / f'{name}-server.log').open('w') as server_log:
            try:
                client = subprocess.Popen(criu + [
                    'pre-dump', '-t', str(parent), '-D', str(source), '-o', 'dump.log', '-v4',
                    '--track-mem', '--pre-dump-mode', 'read', '--page-server',
                    '--address', '127.0.0.1', '--port', str(listener.getsockname()[1])],
                    stdout=client_log, stderr=client_log, env=environment)
                connection, _ = listener.accept()
                with connection:
                    # Faults affect the client only, never the receiver.
                    server = subprocess.Popen(criu + [
                        'page-server', '-D', str(target), '-o', 'server.log', '-v4',
                        '--ps-socket', str(connection.fileno())],
                        pass_fds=[connection.fileno()], stdout=server_log, stderr=server_log)
                    client_status = client.wait(timeout=60)
                    server_status = server.wait(timeout=60)
                return source, target, client_status, server_status
            finally:
                for process in (client, server):
                    if process is not None and process.poll() is None:
                        process.kill()
                        process.wait()


def covers(directory, pid, address, size):
    return any(int(entry['vaddr']) <= address and
               int(entry['vaddr']) + int(entry['nr_pages']) * size >= address + size
               for entry in image_entries(directory, pid))


def case(work, executable, library, mode):
    base = work / mode
    base.mkdir()
    manifest = base / 'workload.txt'
    environment = os.environ.copy()
    for key in ('CRIU_TRACK_SHMEM', 'CRIU_TEST_THP', 'LD_PRELOAD'):
        environment.pop(key, None)
    pids = []
    process = None
    criu = [str(ROOT / 'criu/criu'), '--no-default-config']
    try:
        with (base / 'workload.log').open('w') as log:
            process = subprocess.Popen([str(executable), str(manifest)], stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=log, start_new_session=True, env=environment)
        wait_until(lambda: manifest.exists() and len(manifest.read_text().split()) == 7,
                   'read-fault workload did not start')
        parent, child, private, shared, private_size, shared_size, page_size = map(
            int, manifest.read_text().split())
        pids = [parent, child]
        if process.pid != parent:
            raise RuntimeError('unexpected workload PID')
        injected = dict(environment, LD_PRELOAD=str(library), CRIU_TEST_READ_FAULT=mode,
                        CRIU_TEST_READ_PID=str(parent), CRIU_TEST_READ_BEGIN=str(private),
                        CRIU_TEST_READ_END=str(private + private_size))
        source, target, client_status, server_status = remote_predump(base, 'fault', parent, injected)
        evidence = (base / 'fault-client.log').read_text()
        marker = re.findall(r'READ_FAULT: ([\w-]+) ([\w-]+) (0x[0-9a-f]+|0)', evidence)
        events = [event for name, event, _ in marker if name == mode]
        required = {'short-read': {'armed', 'short'}, 'first-efault': {'armed', 'efault'},
                    'partial-efault': {'armed', 'short', 'efault'},
                    'recovery-esrch': {'armed', 'efault', 'recovery'},
                    'recovery-eperm': {'armed', 'efault', 'recovery'},
                    'zero-read': {'armed', 'zero'}, 'recovery-zero': {'armed', 'efault', 'recovery'},
                    'vmsplice-error': {'error'}, 'vmsplice-short': {'short'}}[mode]
        if not required.issubset(events):
            raise RuntimeError(f'{mode}: fault branch was not exercised: {events}')
        if mode.startswith('recovery-') and events.count('recovery') != 1:
            raise RuntimeError(f'{mode}: terminal recovery result was not propagated immediately')
        if (mode in ERROR_CASES) != (client_status != 0):
            raise RuntimeError(f'{mode}: unexpected client status {client_status}')
        if mode in SUCCESS_CASES and server_status:
            raise RuntimeError(f'{mode}: receiver failed: {server_status}')
        if list(source.glob('.pagemap-*.img.tmp.*')) or list(source.glob('pages-*.img')):
            raise RuntimeError('source retained temporary coverage or payload')
        if mode in ERROR_CASES and list(source.glob('pagemap-*.img')):
            raise RuntimeError('failed read pre-dump published coverage')
        expected = bytearray([0x29]) * private_size
        selected = next((int(address, 0) for name, event, address in marker
                         if name == mode and event == 'armed'), None)
        if mode == 'recovery-esrch':
            for directory in (source, target):
                for entry in image_entries(directory, parent):
                    low = int(entry['vaddr'])
                    high = low + int(entry['nr_pages']) * page_size
                    if low < private + private_size and high > selected:
                        raise RuntimeError('read recovery continued after the target disappeared')
        if mode in ('first-efault', 'partial-efault'):
            for directory in (source, target):
                if covers(directory, parent, selected, page_size):
                    raise RuntimeError('faulty page was incorrectly included in coverage')
                if not covers(directory, parent, selected + page_size, page_size):
                    raise RuntimeError('recovered first auxiliary iovec is missing')
                if mode == 'partial-efault' and not covers(directory, parent, selected - page_size, page_size):
                    raise RuntimeError('successfully read prefix was lost')
            # Model a live mapping becoming readable and changing after the
            # pre-dump. Missing coverage alone does not make a clean page dirty.
            offset = selected - private
            expected[offset:offset + page_size] = bytes([0x6B]) * page_size
            memory(parent, selected, value=bytes([0x6B]) * page_size)
        elif mode == 'short-read':
            for directory in (source, target):
                if not covers(directory, parent, selected, page_size) or \
                        not covers(directory, parent, selected + page_size, page_size):
                    raise RuntimeError('short-read retry lost a readable page')
        if mode in ERROR_CASES or mode == 'recovery-esrch':
            # ESRCH is simulated, so the still-live task needs a fresh baseline.
            # After any failed round soft-dirty may already have been reset;
            # never retry incrementally against an earlier successful parent.
            source, target, retry_status, receiver_status = remote_predump(base, 'retry', parent, environment)
            if retry_status or receiver_status:
                raise RuntimeError('full-baseline recovery failed')
        final = base / 'final'
        final.mkdir()
        run(criu + ['dump', '-t', str(parent), '-D', str(final), '-o', 'dump.log', '-v4',
                    '--track-mem', '--prev-images-dir', '../' + source.name],
            base / 'final-command.log', environment)
        process.wait(timeout=10)
        if mode in ('first-efault', 'partial-efault'):
            if page_flags(final, parent, selected, page_size) != 4 or \
                    page_flags(final, parent, selected + page_size, page_size) != 1:
                raise RuntimeError('final dump did not recopy changed skipped page and inherit readable neighbor')
        if mode == 'short-read' and page_flags(final, parent, selected, page_size) != 1:
            raise RuntimeError('successful short-read page was not inherited')
        (final / 'parent').unlink()
        (final / 'parent').symlink_to('../' + target.name)
        run(criu + ['restore', '-D', str(final), '-o', 'restore.log', '-v4', '-d'],
            base / 'restore-command.log', environment)
        for pid in pids:
            if not alive(pid):
                raise RuntimeError('restored task missing')
            memory(pid, private, bytes(expected) if pid == parent else bytes([0x29]) * private_size)
            memory(pid, shared, bytes([0x19]) * shared_size)
        result = {'case': mode, 'status': 'PASS', 'fault_events': events,
                  'client_status': client_status, 'server_status': server_status,
                  'private_bytes_checked': 2 * private_size, 'shared_bytes_checked': 2 * shared_size}
        (base / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(f'READ-FAULT: PASS {mode}', flush=True)
        return result
    finally:
        for pid in reversed(pids):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()


def main():
    if os.geteuid() != 0:
        raise RuntimeError('run as root on an isolated CRIU test host')
    work = Path(tempfile.mkdtemp(prefix='read-fault-regression.', dir=HERE))
    print(f'Work directory: {work}', flush=True)
    executable, library = work / 'workload', work / 'fail-read.so'
    cc = os.environ.get('CC', 'cc')
    run([cc, '-O2', '-Wall', '-Wextra', '-Werror', HERE / 'shared_workload.c', '-o', executable],
        work / 'compile-workload.log')
    run([cc, '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror', HERE / 'fail_read.c', '-ldl', '-o', library],
        work / 'compile-shim.log')
    results = [case(work, executable, library, mode) for mode in SUCCESS_CASES + ERROR_CASES]
    (work / 'results.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
