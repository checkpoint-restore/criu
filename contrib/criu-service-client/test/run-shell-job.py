#!/usr/bin/env python3

import contextlib
import fcntl
import os
import pathlib
import pty
import shutil
import signal
import subprocess
import sys
import termios
import time

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
CLIENT = str(SCRIPT_DIR / ".." / "criu-service-client")
IMGS_DIR = SCRIPT_DIR / "imgs-shell-job"
MARKER = SCRIPT_DIR / "keep-running"


def setup_local_env():
    """When LOCAL=1 (default), use libcriu and criu from the source tree."""
    if os.environ.get("LOCAL", "1") != "1":
        return
    os.environ["LD_LIBRARY_PATH"] = str(SCRIPT_DIR / ".." / ".install" / "lib")
    criu_bin_dir = str(SCRIPT_DIR / ".." / ".." / ".." / "criu")
    os.environ["PATH"] = criu_bin_dir + ":" + os.environ.get("PATH", "")


def create_pty():
    master, slave = pty.openpty()
    return os.fdopen(master, "wb"), os.fdopen(slave, "wb")


def run_client(args, **kwargs):
    cmd = [CLIENT, *args]
    print(f"Run: {' '.join(cmd)}")
    ret = subprocess.call(cmd, **kwargs)
    if ret != 0:
        print(f"FAIL: {args[0]} returned {ret}")
        sys.exit(1)


def spawn_workload():
    """Fork a child that acts as a shell-job process.

    It starts a new session, attaches a PTY as its controlling terminal,
    and loops until the marker file is removed.  The pipe lets the parent
    wait until the child setup is done.
    """
    master, slave = create_pty()
    rfd, wfd = os.pipe()

    pid = os.fork()
    if pid == 0:
        master.close()
        os.close(rfd)
        os.setsid()
        os.dup2(slave.fileno(), 0)
        os.dup2(slave.fileno(), 1)
        os.dup2(slave.fileno(), 2)
        fcntl.ioctl(slave.fileno(), termios.TIOCSCTTY, 1)
        slave.close()
        # Signal the parent that setup is complete. A byte (rather than
        # EOF-via-close) lets the parent distinguish a completed setup
        # from a child that died mid-setup.
        os.write(wfd, b"\x00")
        os.close(wfd)
        while MARKER.exists():
            time.sleep(1)
        sys.exit(0)

    slave.close()
    os.close(wfd)
    if os.read(rfd, 1) != b"\x00":
        print("FAIL: child exited before completing setup")
        os.close(rfd)
        os.waitpid(pid, 0)
        sys.exit(1)
    os.close(rfd)
    # Return the master fd so it stays open; closing it would send
    # SIGHUP to the child (it is the session leader on this PTY).
    return pid, master


def test_dump(pid):
    run_client(["dump", "-j", "-t", str(pid), "-D", str(IMGS_DIR),
                "-v4", "-o", "dump.log"])
    os.wait()  # Clear the zombie left behind by the dumped child.

    if not (IMGS_DIR / "inventory.img").exists():
        print("FAIL: no inventory image after dump")
        sys.exit(1)
    print("Dump passed")


def test_restore():
    """With --shell-job, CRIU restores the process's terminal by inheriting
    it from the client's stdin.  We fork into a new session with a fresh
    PTY on stdin so the restored process gets a working terminal.
    """
    master, slave = create_pty()
    cpid = os.fork()
    if cpid == 0:
        master.close()
        os.setsid()
        os.dup2(slave.fileno(), 0)
        fcntl.ioctl(0, termios.TIOCSCTTY, 1)
        run_client(["restore", "-j", "-D", str(IMGS_DIR),
                    "-v4", "-o", "restore.log"])
        sys.exit(0)

    _, status = os.wait()
    if status != 0:
        print(f"FAIL: restore exited with {status}")
        sys.exit(1)
    print("Restore passed")


def cleanup(pid, pty_master):
    if pty_master is not None:
        with contextlib.suppress(OSError):
            pty_master.close()
    if MARKER.exists():
        MARKER.unlink()
    if pid is not None:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
        with contextlib.suppress(ChildProcessError):
            os.waitpid(pid, 0)


def main():
    setup_local_env()

    if IMGS_DIR.exists():
        shutil.rmtree(IMGS_DIR)
    IMGS_DIR.mkdir(parents=True)

    # Create a marker file; the child exits when it disappears.
    MARKER.touch()

    pid, pty_master = spawn_workload()
    try:
        test_dump(pid)
        # After a successful dump the workload has been killed and
        # reaped by test_dump(); don't let cleanup() try again.
        pid = None
        pty_master.close()
        pty_master = None

        # Remove the marker so the restored process exits cleanly.
        MARKER.unlink()
        test_restore()
    finally:
        cleanup(pid, pty_master)


if __name__ == "__main__":
    main()
