#!/usr/bin/env python3
"""CUDA mock tests for destructive failures and foreground restore."""

import contextlib
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[3]
MOCK = Path(__file__).with_name("mock")


@contextlib.contextmanager
def target(directory, mixed=False, pass_fds=(), duration=300):
    child_file = directory / "child.pid"
    command = ["sleep", str(duration)]
    if mixed:
        # Only the root holds fault-notification pipes open.
        close_fds = " ".join(f"{fd}>&-" for fd in pass_fds)
        command = ["sh", "-c", f'sleep {duration} {close_fds} & echo $! > "$1"; wait',
                   "sh", str(child_file)]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               pass_fds=pass_fds)
    pids = [process.pid]
    try:
        if mixed:
            deadline = time.monotonic() + 5
            while True:
                child_pid_text = ""
                if child_file.exists():
                    child_pid_text = child_file.read_text().strip()
                if child_pid_text:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("test child did not start")
                time.sleep(0.01)
            pids.append(int(child_pid_text))
        yield process, pids
    finally:
        for pid in reversed(pids):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                # The process may already have exited during the test.
                pass
        process.wait(timeout=5)


def run_criu(directory, pid=None, *, operation="dump", expected_success=False,
             pass_fds=(), **variables):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("CRIU_CUDA_MOCK_")}
    environment.update(CRIU_FAULT="138", LD_LIBRARY_PATH=str(MOCK),
                       PATH=f"{MOCK}:{environment['PATH']}",
                       CRIU_CUDA_MOCK_CLI_MARKER=str(directory / "cli.marker"),
                       **variables)
    command = [str(ROOT / "criu/criu"), operation, "--no-default-config",
               "--images-dir", str(directory), "--log-file", f"{operation}.log",
               "--verbosity=4", "--libdir", str(ROOT / "plugins/cuda"),
               "--shell-job", "--timeout", "10"]
    if operation == "dump":
        command += ["--tree", str(pid)]
    with subprocess.Popen(command, env=environment, pass_fds=pass_fds,
                          start_new_session=True) as result:
        try:
            result.wait(timeout=10)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(result.pid, signal.SIGKILL)
            result.wait()
            raise
    log = (directory / f"{operation}.log").read_text()
    if result.returncode < 0 or (result.returncode == 0) != expected_success:
        raise RuntimeError(f"{directory.name} {operation}: status {result.returncode}\n{log}")
    return log


def assert_untraced(pid):
    status = Path(f"/proc/{pid}/status").read_text()
    assert "TracerPid:\t0\n" in status, status


def test_target_fault(work):
    for behavior, mixed in (("trap", False), ("target-kill", False), ("trap", True)):
        directory = work / f"target-{behavior}-{mixed}"
        directory.mkdir()
        marker = directory / "api.calls"
        reader, writer = os.pipe()
        try:
            with target(directory, mixed=mixed, pass_fds=(writer,)) as (process, pids):
                os.close(writer)
                writer = -1
                log = run_criu(directory, pids[0], pass_fds=(reader,),
                               CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR=behavior,
                               CRIU_CUDA_MOCK_TARGET_PIPE=str(reader),
                               CRIU_CUDA_MOCK_API_MARKER=str(marker))
                assert "failed during Driver API operation" in log
                assert "Dumping FAILED" in log
                assert process.wait(timeout=5) == -signal.SIGKILL
                calls = [line.split() for line in marker.read_text().splitlines()]
                operations = [call[0] for call in calls if int(call[1]) == pids[0]]
                assert "checkpoint" in operations
                assert "restore" not in operations and "unlock" not in operations
                if mixed:
                    os.kill(pids[1], 0)
                    assert_untraced(pids[1])
                    assert any(call[0] == "unlock" and int(call[1]) == pids[1] for call in calls)
        finally:
            os.close(reader)
            if writer >= 0:
                os.close(writer)


def test_traced_fork(work):
    binary = Path(__file__).with_name("fork-target")
    for backend, version in (("Driver API", "13000"), ("cuda-checkpoint CLI", "12000")):
        directory = work / f"fork-{version}"
        directory.mkdir()
        ready = directory / "ready.pid"
        trigger = directory / "clone.trigger"
        clone_pid_file = directory / "clone.pid"
        reader, writer = os.pipe()
        process = None
        try:
            process = subprocess.Popen([str(binary), str(ready), str(trigger), str(clone_pid_file)],
                                       stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL,
                                       pass_fds=(writer,), start_new_session=True)
            os.close(writer)
            writer = -1
            deadline = time.monotonic() + 5
            while not ready.exists() or not ready.read_text().strip():
                if time.monotonic() >= deadline:
                    raise RuntimeError("clone target did not start")
                time.sleep(0.01)
            log = run_criu(directory, process.pid, pass_fds=(reader,),
                           CRIU_CUDA_MOCK_DRIVER_VERSION=version,
                           CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR="fork",
                           CRIU_CUDA_MOCK_TARGET_PIPE=str(reader),
                           CRIU_CUDA_MOCK_FAULT_TRIGGER=str(trigger),
                           CRIU_CUDA_MOCK_CLONE_PID=str(clone_pid_file),
                           CRIU_CUDA_MOCK_STATE_FILE=str(directory / "state"))
            assert f"selected {backend} backend" in log, log
            assert "stopped by signal 5" in log
            assert "Dumping FAILED" in log
            if backend == "Driver API":
                assert process.wait(timeout=5) == -signal.SIGKILL
            else:
                assert process.poll() is None
                assert_untraced(process.pid)
        finally:
            os.close(reader)
            if writer >= 0:
                os.close(writer)
            if process is not None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def test_resume_fault(work):
    for phase in ("init", "restore"):
        directory = work / f"resume-{phase}-fault"
        directory.mkdir()
        marker = directory / "api.calls"
        variables = dict(CRIU_CUDA_MOCK_API_MARKER=str(marker),
                         CRIU_CUDA_MOCK_STATE_FILE=str(directory / "state"))
        with target(directory) as (process, pids):
            run_criu(directory, pids[0], expected_success=True, **variables)
            process.wait(timeout=5)
            marker.unlink()
            log = run_criu(directory, operation="restore",
                           CRIU_CUDA_MOCK_RESUME_FAULT=phase,
                           CRIU_CUDA_MOCK_TARGET_PID=str(pids[0]), **variables)
            assert "selected Driver API backend" in log, log
            assert "failed during Driver API operation" in log, log
            assert "stopped by signal 5" in log, log
            assert "Device hook failed" in log, log
            assert not Path(f"/proc/{pids[0]}").exists(), 'faulted target survived restore'
            calls = [line.split() for line in marker.read_text().splitlines()]
            operations = [call[0] for call in calls]
            assert "init" in operations
            assert ("restore" in operations) == (phase == "restore")
            assert "unlock" not in operations, 'CUDA API reentered after a target fault'
            callers = {int(call[2]) for call in calls}
            for caller in callers:
                assert not Path(f"/proc/{caller}").exists(), f"CUDA caller {caller} leaked"


def test_foreground_restore(work):
    directory = work / "foreground-restore"
    directory.mkdir()
    marker = directory / "api.calls"
    variables = dict(CRIU_CUDA_MOCK_API_MARKER=str(marker),
                     CRIU_CUDA_MOCK_STATE_FILE=str(directory / "state"))
    with target(directory, duration=3) as (process, pids):
        log = run_criu(directory, pids[0], expected_success=True, **variables)
        assert "selected Driver API backend" in log
        process.wait(timeout=5)
        # Foreground restore must wait for the restored workload to exit.
        log = run_criu(directory, operation="restore", expected_success=True, **variables)
        assert "selected Driver API backend" in log
        assert not Path(f"/proc/{pids[0]}").exists()
        assert not (directory / "cli.marker").exists()
        callers = {int(line.split()[2]) for line in marker.read_text().splitlines()}
        assert callers
        for caller in callers:
            assert not Path(f"/proc/{caller}").exists(), f"CUDA caller {caller} leaked"


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("these checks use assert; run without python -O")
    with tempfile.TemporaryDirectory(prefix="criu-cuda-backend-errors-") as directory:
        work = Path(directory)
        test_target_fault(work)
        test_traced_fork(work)
        test_resume_fault(work)
        test_foreground_restore(work)
    print("CUDA backend regression tests PASS")
