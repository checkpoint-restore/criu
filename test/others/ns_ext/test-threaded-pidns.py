#!/usr/bin/env python3
"""Restore into a different live PID namespace with a threaded late plugin."""

import argparse
import json
import os
from pathlib import Path
import shutil
import select
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent


def namespace_init(fd, source):
    if source:
        pid = os.fork()
        if pid == 0:
            os.close(fd)
            os.setsid()
            os.execl("/bin/sleep", "sleep", "300")
    # /proc is inherited from the caller, so Pid names this task there.
    status = Path("/proc/self/status").read_text()
    host_pid = next(line.split()[1] for line in status.splitlines()
                    if line.startswith("Pid:"))
    os.write(fd, f"{host_pid}\n".encode())
    os.close(fd)
    while True:
        try:
            os.wait()
        except ChildProcessError:
            signal.pause()


def start_namespace(source):
    read_fd, write_fd = os.pipe()
    command = ["unshare", "--pid", "--fork", "--kill-child=KILL", "--",
               sys.executable, str(HERE / "test-threaded-pidns.py"),
               "--namespace-init", str(write_fd)]
    if source:
        command.append("--source")
    try:
        process = subprocess.Popen(
            command, pass_fds=(write_fd,), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL)
    except BaseException:
        os.close(read_fd)
        raise
    finally:
        os.close(write_fd)
    try:
        with os.fdopen(read_fd) as pipe:
            if not select.select([pipe], [], [], 5)[0]:
                raise RuntimeError("namespace init did not report its PID")
            pid = int(pipe.readline())
        return process, pid
    except BaseException:
        process.kill()
        process.wait()
        raise


def wait_worker(init):
    children = Path(f"/proc/{init}/task/{init}/children")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        for pid in children.read_text().split():
            if Path(f"/proc/{pid}/comm").read_text().strip() == "sleep":
                return int(pid)
        time.sleep(0.01)
    raise RuntimeError("source sleep did not start")


def check_restore(criu, directory, source, destination):
    source_ns = Path(f"/proc/{source}/ns/pid")
    destination_ns = Path(f"/proc/{destination}/ns/pid")
    namespace = os.stat(source_ns).st_ino
    if namespace == os.stat(destination_ns).st_ino:
        raise RuntimeError("source and destination PID namespaces are identical")
    if os.stat(destination_ns).st_ino == os.stat("/proc/self/ns/pid").st_ino:
        raise RuntimeError("destination PID namespace is the caller's namespace")

    common = ["--no-default-config", "-D", str(directory), "-v4", "--shell-job",
              "--manage-cgroups=ignore", "--libdir", str(HERE)]
    subprocess.run([str(criu), "dump", *common, "-t", str(source), "-o", "dump.log",
                    "--external", f"pid[{namespace}]:target-pidns"],
                   check=True, timeout=30)
    with destination_ns.open() as namespace_fd:
        subprocess.run(
            [str(criu), "restore", *common, "-o", "restore.log", "--restore-detached",
             "--inherit-fd", f"fd[{namespace_fd.fileno()}]:target-pidns",
             "--pidfile", str(directory / "restored.pid")],
            pass_fds=(namespace_fd.fileno(),), check=True, timeout=30)

    restored = int((directory / "restored.pid").read_text())
    if os.stat(f"/proc/{restored}/ns/pid").st_ino != os.stat(destination_ns).st_ino:
        raise RuntimeError("restored task did not join the destination PID namespace")
    log = (directory / "restore.log").read_text()
    if log.count("pidns-thread-test: plugin thread completed for ") != 1:
        raise RuntimeError("late plugin did not create and join exactly one thread")
    print(json.dumps({"restored_pid": restored, "destination_init": destination,
                      "plugin_thread_completed": True}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--criu", type=Path, default=HERE / "../../../criu/criu")
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--keep-images", action="store_true")
    parser.add_argument("--namespace-init", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--source", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.namespace_init is not None:
        namespace_init(args.namespace_init, args.source)
        return
    if os.geteuid() != 0:
        parser.error("run as root to create PID namespaces and checkpoint tasks")

    directory = Path(tempfile.mkdtemp(prefix="criu-threaded-pidns-", dir=args.work_dir))
    processes = []
    succeeded = False
    try:
        source_process, source_init = start_namespace(True)
        processes.append(source_process)
        destination_process, destination_init = start_namespace(False)
        processes.append(destination_process)
        check_restore(args.criu.resolve(), directory, wait_worker(source_init), destination_init)
        succeeded = True
        print("PASS: plugin thread after external PID namespace restore", flush=True)
    finally:
        # Killing each test-owned namespace init also kills its restored tasks.
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        if succeeded and not args.keep_images:
            shutil.rmtree(directory)
        else:
            print(f"Images and logs: {directory}", flush=True)


if __name__ == "__main__":
    main()
