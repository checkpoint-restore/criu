#!/usr/bin/env python3
"""Redis in runc: remote pre-dump chain, receiver dedup, local final, and restore."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
from socket import AF_INET, SOCK_STREAM, socket as Socket
import subprocess
import sys
import tempfile
import time

from redis_oracle import RedisClient, RedisOracle

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'lib'))


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def payload(directory):
    pages = list(directory.glob('pages-*.img'))
    maps = list(directory.glob('pagemap-*.img'))
    return {'pages_files': len(pages), 'pages_bytes': sum(p.stat().st_size for p in pages),
            'pages_allocated_bytes': sum(p.stat().st_blocks * 512 for p in pages),
            'pagemap_files': len(maps), 'pagemap_bytes': sum(p.stat().st_size for p in maps)}


def pagemaps(directory):
    import pycriu.images
    result = []
    for path in sorted(directory.glob('pagemap-*.img')):
        with path.open('rb') as image:
            entries = pycriu.images.load(image)['entries']
        result.append((path.name, entries))
    return result


def page_counts(directory):
    counts = {'present': 0, 'parent': 0}
    for _, entries in pagemaps(directory):
        for entry in entries[1:]:
            flags = int(entry.get('flags', 0))
            if flags & 4:
                counts['present'] += int(entry['nr_pages'])
            if flags & 1:
                counts['parent'] += int(entry['nr_pages'])
    return counts


def validate_source(source, candidate):
    metrics = payload(source)
    if metrics['pages_files'] or list(source.glob('.pagemap-*.img.tmp.*')):
        raise RuntimeError('source retained pre-dump payload or temporary coverage')
    maps = pagemaps(source)
    if candidate:
        if not maps or any(int(entries[0]['pages_id']) != 0 for _, entries in maps):
            raise RuntimeError('source is missing coverage-only pagemaps')
    elif maps:
        raise RuntimeError('pre-feature control unexpectedly created source coverage')
    return metrics


def validate_destination(directory, parent):
    maps = pagemaps(directory)
    if not maps or any(int(entries[0]['pages_id']) == 0 for _, entries in maps):
        raise RuntimeError('destination does not have ordinary payload pagemaps')
    link = directory / 'parent'
    if parent is not None:
        if not link.is_symlink() or link.resolve(strict=True) != parent.resolve(strict=True):
            raise RuntimeError('destination parent link selects the wrong generation')
    elif link.exists() or link.is_symlink():
        raise RuntimeError('first destination round unexpectedly has a parent')


def dynamic_libraries(executable):
    output = subprocess.check_output(['ldd', str(executable)], text=True,
                                     env=dict(os.environ, LC_ALL='C'))
    if 'not found' in output:
        raise RuntimeError('Redis binary has unresolved shared libraries')
    paths = set()
    for line in output.splitlines():
        match = re.search(r'(?:=>\s+)?(/\S+)\s+\(', line)
        if match:
            paths.add(Path(match[1]))
    if not paths:
        raise RuntimeError('could not determine Redis runtime libraries')
    return sorted(paths)


def copy_binary(rootfs, source, destination):
    target = rootfs / destination.lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source.resolve(strict=True), target)


def prepare_rootfs(rootfs, redis, launcher):
    rootfs.mkdir()
    for directory in ('dev', 'proc', 'sys', 'tmp', 'run', 'data', 'etc', 'usr/bin'):
        (rootfs / directory).mkdir(parents=True, exist_ok=True)
    (rootfs / 'tmp').chmod(0o1777)
    copy_binary(rootfs, redis, '/usr/bin/redis-server')
    copy_binary(rootfs, launcher, '/usr/bin/base-page-launcher')
    libraries = set(dynamic_libraries(redis)) | set(dynamic_libraries(launcher))
    for library in sorted(libraries):
        copy_binary(rootfs, library, str(library))
    (rootfs / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/false\n')
    (rootfs / 'etc/group').write_text('root:x:0:\n')
    return [{'path': '/' + str(path.relative_to(rootfs)), 'sha256': sha256(path)}
            for path in sorted(rootfs.rglob('*')) if path.is_file()]


class Commands:
    def __init__(self, directory, environment):
        self.directory = directory
        self.environment = environment
        self.history = []

    def record(self, command, label, cwd=None):
        self.history.append({'label': label, 'argv': [str(arg) for arg in command],
                             'cwd': str(cwd) if cwd else None})
        save(self.directory / 'commands.json', self.history)

    def run(self, command, label, cwd=None, timeout=120, check=True):
        self.record(command, label, cwd)
        with (self.directory / (label + '.log')).open('w') as log:
            return subprocess.run([str(arg) for arg in command], cwd=cwd,
                                  env=self.environment, stdin=subprocess.DEVNULL,
                                  stdout=log, stderr=subprocess.STDOUT,
                                  timeout=timeout, check=check)


def wait_redis(port, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with RedisClient('127.0.0.1', port, timeout=1) as client:
                if client.command('PING') == b'PONG':
                    return
        except (OSError, RuntimeError):
            pass
        time.sleep(0.05)
    raise RuntimeError('Redis service did not become ready')


def cleanup_containers(commands, runtimes, container, failed):
    errors = []
    for runtime, label in runtimes:
        try:
            commands.run(runtime + ['delete', '--force', container], label, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError) as error:
            errors.append(f'{label}: {error}')
    if errors:
        message = 'container cleanup failed: ' + '; '.join(errors)
        if not failed:
            raise RuntimeError(message)
        # Keep the checkpoint/restore error when cleanup also fails.
        print(message, file=sys.stderr)


def case(work, runc, redis, criu, candidate, launcher, rounds):
    label = 'candidate' if candidate else 'baseline'
    base = work / label
    base.mkdir()
    result = {'case': label, 'status': 'FAIL', 'rounds': [],
              'receiver_auto_dedup': True, 'predump_mode': 'splice',
              'cgroups_mode': 'ignore'}
    source_bundle, target_bundle = base / 'source-bundle', base / 'target-bundle'
    source_bundle.mkdir()
    target_bundle.mkdir()
    source_images, target_images = base / 'source-images', base / 'target-images'
    source_images.mkdir()
    target_images.mkdir()
    source_state, target_state = base / 'source-state', base / 'target-state'
    container = 'redis-' + base.parent.name.replace('.', '-') + '-' + label
    binary_dir = base / 'bin'
    binary_dir.mkdir()
    # runc finds CRIU via PATH; the wrapper also excludes host CRIU config.
    wrapper = binary_dir / 'criu'
    wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(str(criu)) + ' --no-default-config "$@"\n')
    wrapper.chmod(0o755)
    environment = {'PATH': str(binary_dir) + ':/usr/sbin:/usr/bin:/sbin:/bin',
                   'HOME': '/root', 'LANG': 'C', 'LC_ALL': 'C'}
    commands = Commands(base, environment)
    source_runtime = [runc, '--debug', '--log', base / 'source-runc.log', '--root', source_state]
    target_runtime = [runc, '--debug', '--log', base / 'target-runc.log', '--root', target_state]
    server = client = None
    with Socket(AF_INET, SOCK_STREAM) as selector:
        selector.bind(('127.0.0.1', 0))
        redis_port = selector.getsockname()[1]
    try:
        save(base / 'rootfs-files.json', prepare_rootfs(source_bundle / 'rootfs', redis, launcher))
        commands.run([runc, 'spec'], 'runc-spec', cwd=source_bundle)
        config = json.loads((source_bundle / 'config.json').read_text())
        config['root'] = {'path': 'rootfs', 'readonly': False}
        config['process']['terminal'] = False
        config['process']['cwd'] = '/data'
        config['process']['env'] = ['PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C']
        config['process']['args'] = ['/usr/bin/base-page-launcher', '/usr/bin/redis-server',
                                     '--bind', '127.0.0.1', '--port', str(redis_port),
                                     '--protected-mode', 'yes', '--save', '', '--appendonly', 'no',
                                     '--daemonize', 'no', '--dir', '/data', '--logfile', '',
                                     '--databases', '1', '--hz', '1']
        config['linux']['namespaces'] = [ns for ns in config['linux']['namespaces']
                                         if ns['type'] not in ('network', 'cgroup')]
        # Host networking isolates this test from network-device migration;
        # mount/PID/UTS/IPC namespaces and the actual Redis process are restored.
        save(source_bundle / 'config.json', config)
        shutil.copytree(source_bundle / 'rootfs', target_bundle / 'rootfs', symlinks=True)
        shutil.copy2(source_bundle / 'config.json', target_bundle / 'config.json')
        # Keep standard fds attached to /dev/null, not a controller pipe or log
        # outside the rootfs that could accidentally become a restore dependency.
        command = source_runtime + ['run', '--detach', '--bundle', source_bundle,
                                    '--pid-file', base / 'source.pid', container]
        commands.record(command, 'runc-run')
        with open(os.devnull, 'r+b') as null:
            subprocess.run([str(arg) for arg in command], env=environment, stdin=null,
                           stdout=null, stderr=null, check=True, timeout=30)
        wait_redis(redis_port)
        oracle = RedisOracle()
        with RedisClient('127.0.0.1', redis_port) as connection:
            oracle.seed(connection)
        prior_source = prior_target = None
        for iteration in range(1, rounds + 1):
            source = source_images / f'round-{iteration}'
            target = target_images / f'round-{iteration}'
            source.mkdir()
            target.mkdir()
            parent_before = payload(prior_target) if prior_target else None
            with Socket(AF_INET, SOCK_STREAM) as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                listener.settimeout(30)
                command = source_runtime + ['checkpoint', '--pre-dump', '--image-path', source,
                                             '--work-path', source, '--manage-cgroups-mode', 'ignore',
                                             '--page-server', f'127.0.0.1:{listener.getsockname()[1]}']
                if prior_source:
                    command += ['--parent-path', '../' + prior_source.name]
                command += [container]
                commands.record(command, f'predump-{iteration}')
                with (base / f'predump-{iteration}.log').open('w') as client_log:
                    client = subprocess.Popen([str(arg) for arg in command], env=environment,
                                              stdin=subprocess.DEVNULL, stdout=client_log, stderr=client_log)
                    accepted, _ = listener.accept()
                    with accepted, (base / f'receiver-{iteration}.log').open('w') as server_log:
                        command = [criu, '--no-default-config', 'page-server', '-D', target,
                                   '-o', 'server.log', '-v4', '--auto-dedup', '--ps-socket', str(accepted.fileno())]
                        if prior_target:
                            command += ['--prev-images-dir', '../' + prior_target.name]
                        commands.record(command, f'receiver-{iteration}')
                        server = subprocess.Popen([str(arg) for arg in command], env=environment,
                                                  pass_fds=[accepted.fileno()], stdout=server_log, stderr=server_log)
                        client_status = client.wait(timeout=120)
                        server_status = server.wait(timeout=120)
                        if client_status or server_status:
                            raise RuntimeError(f'pre-dump {iteration} failed: client={client_status}, receiver={server_status}')
                        server = client = None
            source_metrics = validate_source(source, candidate)
            validate_destination(target, prior_target)
            target_metrics = payload(target)
            punches = (target / 'server.log').read_text().count('Punch!/')
            if iteration > 1 and not punches:
                raise RuntimeError('receiver auto-dedup did not exercise parent hole-punching')
            result['rounds'].append({'iteration': iteration, 'source': source_metrics,
                                     'receiver': target_metrics, 'dedup_punches': punches,
                                     'parent_before': parent_before,
                                     'parent_after': payload(prior_target) if prior_target else None})
            save(base / 'result.json', result)
            with RedisClient('127.0.0.1', redis_port) as connection:
                oracle.mutate(connection, iteration)
            prior_source, prior_target = source, target
        final = source_images / 'final'
        final.mkdir()
        command = source_runtime + ['checkpoint', '--image-path', final, '--work-path', final,
                                     '--shell-job', '--tcp-established', '--manage-cgroups-mode', 'ignore',
                                     '--parent-path', '../' + prior_source.name, container]
        # Every page server and listening socket above has exited/closed.
        # The final is deliberately local and receives no --page-server option.
        commands.run(command, 'local-final')
        if commands.run(source_runtime + ['state', container], 'source-after-final', check=False).returncode == 0:
            raise RuntimeError('source container state survived the final checkpoint')
        with Socket(AF_INET, SOCK_STREAM) as probe:
            probe.settimeout(1)
            if probe.connect_ex(('127.0.0.1', redis_port)) == 0:
                raise RuntimeError('original Redis listener is still running after final checkpoint')
        result['source_stopped_before_restore'] = True
        result['final'] = payload(final)
        result['final']['page_counts'] = page_counts(final)
        receiver_hashes = {str(path.relative_to(target_images)): sha256(path)
                           for path in target_images.glob('round-*/pagemap-*.img')}
        destination_final = target_images / 'final'
        shutil.copytree(final, destination_final, symlinks=True)
        # Copy only the final images. Source coverage must never overwrite a
        # receiver pagemap, even though the relative parent names are the same.
        for name, expected in receiver_hashes.items():
            if sha256(target_images / name) != expected:
                raise RuntimeError('final transfer overwrote a receiver pagemap')
        for source in final.iterdir():
            target = destination_final / source.name
            if source.is_file() and not source.is_symlink() and sha256(source) != sha256(target):
                raise RuntimeError('final image transfer changed file contents')
        validate_destination(destination_final, prior_target)
        transfer_bytes = sum(path.stat().st_size for path in final.iterdir()
                             if path.is_file() and not path.is_symlink())
        result['final']['transferred_image_bytes'] = transfer_bytes
        result['final']['source_coverage_copied'] = False
        # Restore with a separate runtime state and rootfs bundle. No page server
        # is running and the entire destination parent chain is already local.
        commands.run(target_runtime + ['restore', '--detach', '--bundle', target_bundle,
                                        '--image-path', destination_final, '--work-path', destination_final,
                                        '--pid-file', base / 'restored.pid', '--shell-job', '--tcp-established',
                                        '--manage-cgroups-mode', 'ignore', container], 'restore')
        wait_redis(redis_port)
        with RedisClient('127.0.0.1', redis_port) as connection:
            result['redis'] = oracle.verify(connection)
        initial = result['rounds'][0]['receiver']['pages_bytes']
        if initial < 32 << 20:
            raise RuntimeError('initial Redis payload is too small for the seeded dataset')
        if candidate:
            if any(entry['receiver']['pages_bytes'] * 2 >= initial for entry in result['rounds'][1:]):
                raise RuntimeError('later remote pre-dumps did not remain incremental')
            if result['final']['pages_bytes'] * 2 >= initial:
                raise RuntimeError('local final recopied too much of the initial Redis payload')
            if not result['final']['page_counts']['parent'] or not result['final']['page_counts']['present']:
                raise RuntimeError('local final did not mix inherited and newly dirty pages')
        elif result['final']['pages_bytes'] < 32 << 20:
            raise RuntimeError('pre-feature control unexpectedly avoided the full Redis payload')
        result['status'] = 'PASS'
        result['final_to_initial_payload_ratio'] = result['final']['pages_bytes'] / initial
        return result
    except Exception as error:
        result['status'] = 'FAIL'
        result['error'] = str(error)
        raise
    finally:
        save(base / 'result.json', result)
        for process in (client, server):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
        try:
            cleanup_containers(commands, ((target_runtime, 'target-cleanup'),
                                          (source_runtime, 'source-cleanup')),
                               container, failed=result['status'] != 'PASS')
        except RuntimeError as error:
            result.update(status='FAIL', error=str(error))
            raise
        finally:
            save(base / 'result.json', result)


def executable(value, name):
    path = Path(value) if value else Path(shutil.which(name) or '')
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f'{name} executable is unavailable: {value or name}')
    # Debian's redis-server is a symlink to a multicall binary which selects
    # its mode from argv[0]. Resolving that symlink invokes redis-check-rdb.
    return Path(os.path.abspath(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--criu', default=os.environ.get('CRIU', str(ROOT / 'criu/criu')))
    parser.add_argument('--baseline-criu', default=os.environ.get('BASELINE_CRIU'))
    parser.add_argument('--runc', default=os.environ.get('RUNC'))
    parser.add_argument('--redis-server', default=os.environ.get('REDIS_SERVER'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('run on an isolated root-capable CRIU/runc test host')
    runc, redis = executable(args.runc, 'runc'), executable(args.redis_server, 'redis-server')
    criu = executable(args.criu, 'criu')
    baseline = executable(args.baseline_criu, 'criu') if args.baseline_criu else None
    work = Path(tempfile.mkdtemp(prefix='runc-redis-regression.', dir=HERE))
    print(f'Work directory: {work}', flush=True)
    commands = Commands(work, os.environ.copy())
    for command, label in (([runc, '--version'], 'runc-version'),
                           ([redis, '--version'], 'redis-version'), ([criu, '--version'], 'criu-version')):
        commands.run(command, label)
    if baseline:
        commands.run([baseline, '--version'], 'baseline-version')
    launcher = work / 'base-page-launcher'
    commands.run([os.environ.get('CC', 'cc'), '-O2', '-Wall', '-Wextra', '-Werror',
                  HERE / 'base_page_launcher.c', '-o', launcher], 'compile-launcher')
    results = []
    for binary, candidate in ((criu, True), (baseline, False)):
        if binary is None:
            continue
        result = case(work, runc, redis, binary, candidate, launcher, 3)
        results.append(result)
        print('RUNC-REDIS: PASS ' + result['case'] + ' ' + json.dumps(result['final']), flush=True)
    if baseline:
        candidate_bytes, baseline_bytes = (item['final']['pages_bytes'] for item in results)
        if candidate_bytes * 2 >= baseline_bytes:
            raise RuntimeError('candidate final payload did not improve on the pre-feature control')
    save(work / 'results.json', results)
    summary = {'status': 'PASS', 'cases': [item['case'] for item in results],
               'comparison': None if not baseline else {
                   'candidate_final_pages_bytes': candidate_bytes,
                   'baseline_final_pages_bytes': baseline_bytes,
                   'payload_ratio': candidate_bytes / baseline_bytes}}
    save(work / 'result.json', summary)
    print('RUNC-REDIS: PASS suite ' + json.dumps(summary), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f'RUNC-REDIS: FAIL {error}', file=sys.stderr)
        sys.exit(1)
