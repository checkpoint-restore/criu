#!/usr/bin/env python3
"""Regression tests for CUDA discovery, inventory allocation, and guarded backend errors.

Requires a built CRIU, CUDA plugin, and test/cuda-checkpoint mocks. All targets
are ordinary CPU processes; neither backend accesses a real GPU.
"""

import contextlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
MOCK = ROOT / "test/cuda-checkpoint"


@contextlib.contextmanager
def target(directory, mixed=False, duration=300):
    child_file = directory / "child.pid"
    command = ["sleep", str(duration)]
    if mixed:
        command = ["sh", "-c", 'sleep 300 & echo $! > "$1"; wait',
                   "sh", str(child_file)]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pids = [process.pid]
    try:
        if mixed:
            deadline = time.monotonic() + 5
            while not child_file.exists() or not child_file.read_text().strip():
                if time.monotonic() >= deadline:
                    raise RuntimeError("test child did not start")
                time.sleep(0.01)
            pids.append(int(child_file.read_text()))
        yield process, pids
    finally:
        for pid in reversed(pids):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                # The process may already have exited during the test.
                pass
        process.wait(timeout=5)


def run_criu(directory, operation, *, pid=None, plugin=None, library=None,
             expected_success=True,
             restore_detached=True, command_timeout=30, freezing_timeout=10,
             plugin_timeout=None, **variables):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("CRIU_CUDA_MOCK_")}
    environment.update(CRIU_FAULT="138", LD_LIBRARY_PATH=str(library or MOCK),
                       PATH=f"{MOCK}:{environment['PATH']}",
                       CRIU_CUDA_MOCK_CLI_MARKER=str(directory / "cli.marker"),
                       **variables)
    command = [str(ROOT / "criu/criu"), operation, "--no-default-config",
               "--images-dir", str(directory), "--log-file", f"{operation}.log",
               "--verbosity=4", "--libdir", str(plugin or ROOT / "plugins/cuda"),
               "--shell-job", "--timeout", str(freezing_timeout)]
    if plugin_timeout is not None:
        command += ["--plugin-option", f"cuda_plugin.timeout={plugin_timeout}"]
    if operation == "dump":
        command += ["--tree", str(pid)]
    elif restore_detached:
        command += ["--restore-detached"]
    result = subprocess.run(command, env=environment, timeout=command_timeout)
    log = (directory / f"{operation}.log").read_text()
    if (result.returncode == 0) != expected_success:
        raise RuntimeError(f"{directory.name} {operation}: status {result.returncode}\n{log}")
    return log


def assert_untraced(pid):
    status = Path(f"/proc/{pid}/status").read_text()
    assert "TracerPid:\t0\n" in status, status


def test_discovery(work):
    for error in (1, 3):  # INVALID_VALUE and NOT_INITIALIZED mean non-CUDA here.
        directory = work / f"cpu-{error}"
        directory.mkdir()
        with target(directory) as (process, pids):
            log = run_criu(directory, "dump", pid=pids[0],
                           CRIU_CUDA_MOCK_TID_ERROR=str(error))
            assert "selected Driver API backend" in log
            process.wait(timeout=5)
            # No CUDA requirement may have been recorded for this CPU-only image.
            log = run_criu(directory, "restore", CRIU_CUDA_MOCK_DRIVER_VERSION_ERROR="1")
            assert "selected Driver API backend" not in log
            assert not (directory / "cli.marker").exists()
            assert_untraced(pids[0])

    directory = work / "mixed"
    directory.mkdir()
    with target(directory, mixed=True) as (process, pids):
        variables = dict(CRIU_CUDA_MOCK_TID_ERROR="3", CRIU_CUDA_MOCK_CUDA_PID=str(pids[1]))
        log = run_criu(directory, "dump", pid=pids[0], **variables)
        assert f"Checkpointing CUDA devices on pid {pids[1]} " in log
        assert f"Checkpointing CUDA devices on pid {pids[0]} " not in log
        process.wait(timeout=5)
        log = run_criu(directory, "restore", CRIU_CUDA_MOCK_INITIAL_STATE="checkpointed", **variables)
        assert f"resuming devices on pid {pids[1]}\n" in log
        assert f"resuming devices on pid {pids[0]}\n" not in log
        assert not (directory / "cli.marker").exists()
        for pid in pids:
            assert_untraced(pid)

    directory = work / "discovery-error"
    directory.mkdir()
    with target(directory) as (process, pids):
        log = run_criu(directory, "dump", pid=pids[0], expected_success=False,
                       CRIU_CUDA_MOCK_TID_ERROR="999")
        assert f"cuCheckpointProcessGetRestoreThreadId({pids[0]}) failed" in log
        assert "(999)" in log
        assert not (directory / "cli.marker").exists()
        assert process.poll() is None
        assert_untraced(pids[0])


def build_inventory_failure_plugin(work):
    # Reuse the plugin's own source list, including at intermediate series commits.
    # Build in a private directory so the normal plugin is never replaced.
    directory = work / "inventory-plugin"
    directory.mkdir()
    source = ROOT / "plugins/cuda"
    for path in [source / "Makefile", *source.glob("*.[ch]"), *source.glob("*.proto")]:
        shutil.copy2(path, directory / path.name)
    machine = os.uname().machine
    arch = {"x86_64": "x86", "aarch64": "arm64"}.get(machine, machine)
    includes = " ".join(f"-iquote{ROOT / path}" for path in
                        ("include", "criu/include", f"criu/arch/{arch}/include", "."))
    subprocess.run(["make", "--no-print-directory", "-C", str(directory), "cuda_plugin.so",
                    f"ARCH={arch}", f"COMPEL={ROOT / 'compel/compel-host'}",
                    f"__nmk_dir={ROOT / 'scripts/nmk/scripts'}/",
                    f"PLUGIN_INCLUDE={includes}", "DEFINES=-D_GNU_SOURCE",
                    f"PLUGIN_LDFLAGS=-Wl,--wrap,add_inventory_plugin {MOCK / 'inventory-failure.c'}"],
                   check=True, timeout=30)
    return directory


def test_inventory_failure(work):
    plugin = build_inventory_failure_plugin(work)
    for backend, library in (("Driver API", MOCK), ("cuda-checkpoint CLI", MOCK / "unsupported")):
        directory = work / ("inventory-driver" if library == MOCK else "inventory-cli")
        directory.mkdir()
        marker = directory / "lock.marker"
        with target(directory) as (process, pids):
            log = run_criu(directory, "dump", pid=pids[0], plugin=plugin, library=library,
                           expected_success=False, CRIU_CUDA_MOCK_LOCK_MARKER=str(marker))
            assert f"selected {backend} backend" in log
            assert "Failed to add CUDA plugin to inventory image" in log
            assert not marker.exists(), "inventory allocation failed after locking CUDA"
            assert "Unable to restore CUDA state" not in log
            assert process.poll() is None
            assert_untraced(pids[0])


def test_foreground_restore(work):
    directory = work / "foreground-restore"
    directory.mkdir()
    marker = directory / "api.calls"
    with target(directory, duration=3) as (process, pids):
        log = run_criu(directory, "dump", pid=pids[0],
                       CRIU_CUDA_MOCK_API_MARKER=str(marker))
        assert "selected Driver API backend" in log
        process.wait(timeout=5)
        # The persistent Driver API worker must not enter CRIU's foreground
        # wait for restored children, or restore never returns after sleep exits.
        log = run_criu(directory, "restore", restore_detached=False,
                       command_timeout=10, CRIU_CUDA_MOCK_INITIAL_STATE="checkpointed",
                       CRIU_CUDA_MOCK_API_MARKER=str(marker))
        assert "selected Driver API backend" in log
        assert not Path(f"/proc/{pids[0]}").exists()
        assert not (directory / "cli.marker").exists()
        workers = {int(line.split()[2]) for line in marker.read_text().splitlines()}
        assert workers
        for worker in workers:
            assert not Path(f"/proc/{worker}").exists(), f"CUDA worker {worker} leaked"


def test_freezing_timeout(work):
    cases = (("Driver API", MOCK, "1"),
             ("cuda-checkpoint CLI", MOCK / "unsupported", "1"),
             ("cuda-checkpoint CLI", MOCK / "unsupported", "closed-output"))
    for backend, library, behavior in cases:
        directory = work / f"freezing-timeout-{library.name}-{behavior}"
        directory.mkdir()
        marker = directory / "api.calls"
        with target(directory) as (process, pids):
            start = time.monotonic()
            log = run_criu(directory, "dump", pid=pids[0], library=library,
                           expected_success=False, freezing_timeout=1,
                           plugin_timeout=30, command_timeout=10,
                           CRIU_CUDA_MOCK_LOCK_HANG=behavior,
                           CRIU_CUDA_MOCK_API_MARKER=str(marker))
            assert time.monotonic() - start < 5
            assert f"selected {backend} backend" in log
            assert "interrupted by CRIU's freezing timeout" in log
            assert "FATAL: Unable to interrupt" not in log
            assert "Dumping FAILED" in log
            assert process.poll() is None
            assert_untraced(pids[0])
            workers = {int(line.split()[2]) for line in marker.read_text().splitlines()}
            assert workers
            for worker in workers:
                assert not Path(f"/proc/{worker}").exists(), f"CUDA helper {worker} leaked"


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="criu-cuda-backend-errors-") as directory:
        work = Path(directory)
        test_discovery(work)
        test_inventory_failure(work)
        test_foreground_restore(work)
        test_freezing_timeout(work)
    print("CUDA backend error regression tests PASS")
