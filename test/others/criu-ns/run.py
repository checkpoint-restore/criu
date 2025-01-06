#!/usr/bin/env python3

import fcntl
import os
import pathlib
import pty
import shutil
import subprocess
import sys
import termios
import time


CRIU_BIN = "../../../criu/criu"
CRIU_NS = "../../../scripts/criu-ns"
IMG_DIR = "dumpdir"
DUMP_LOG = "dump.log"
RESTORE_LOG = "restore.log"
PIDFILE = "pidfile"


def check_dumpdir(path=IMG_DIR):
    if os.path.isdir(path):
        shutil.rmtree(path)
    os.mkdir(path, 0o755)


def run_task_with_own_pty(task):
    fd_m, fd_s = pty.openpty()

    pid = os.fork()
    if pid == 0:
        os.close(fd_m)
        os.setsid()
        os.dup2(fd_s, 0)
        os.dup2(fd_s, 1)
        os.dup2(fd_s, 2)
        fcntl.ioctl(fd_s, termios.TIOCSCTTY, 1)
        os.close(fd_s)
        task()
        exit(0)

    os.close(fd_s)
    fd_m = os.fdopen(fd_m, "rb")
    os.set_blocking(fd_m.fileno(), False)

    while True:
        try:
            data = fd_m.read()
        except IOError:
            break
        if data is not None:
            print(data.decode("utf-8"))

    _, status = os.waitpid(pid, 0)

    try:
        data = fd_m.read()
    except IOError as err:
        print(err)

    if data is not None:
        print(data.decode("utf-8"))
    fd_m.close()

    if status != 0:
        print("task %s exited badly: %d" % (task.__name__, status))
        exit(1)

    return 0


def create_pty():
    fd_m, fd_s = pty.openpty()
    return (os.fdopen(fd_m, "wb"), os.fdopen(fd_s, "wb"))


def create_isolated_dumpee():
    pathlib.Path("running").touch()
    fd_m, fd_s = create_pty()
    pid = os.fork()
    if pid == 0:
        os.setsid()
        os.dup2(fd_s.fileno(), 0)
        os.dup2(fd_s.fileno(), 1)
        os.dup2(fd_s.fileno(), 2)
        fcntl.ioctl(fd_s.fileno(), termios.TIOCSCTTY, 1)
        while True:
            if not os.access("running", os.F_OK):
                sys.exit(0)
            time.sleep(1)
    fd_m.close()
    fd_s.close()
    return pid


def criu_ns_dump(pid, shell_job=False):
    cmd = [CRIU_NS, "dump", "-D", IMG_DIR, "-v4", "-t", str(pid),
           "--log-file", DUMP_LOG, "--criu-binary", CRIU_BIN]
    if shell_job:
        cmd.append("--shell-job")
    ret = subprocess.Popen(cmd).wait()
    return ret


def criu_ns_restore(shell_job=False, restore_detached=False):
    cmd = [CRIU_NS, "restore", "-D", IMG_DIR, "-v4", "--log-file",
           RESTORE_LOG, "--criu-binary", CRIU_BIN]
    if shell_job:
        cmd.append("--shell-job")
    if restore_detached:
        cmd += ["--restore-detached", "--pidfile", PIDFILE]
    ret = subprocess.Popen(cmd).wait()
    return ret


def read_log_file(filename):
    logfile_path = os.path.join(IMG_DIR, filename)
    with open(logfile_path) as logfile:
        print(logfile.read())


def test_dump_and_restore_with_shell_job():
    print("Test criu-ns dump and restore with --shell-job option")
    check_dumpdir()
    pathlib.Path("running").touch()
    pid = os.fork()
    if pid == 0:
        while True:
            if not os.access("running", os.F_OK):
                sys.exit(0)
            time.sleep(1)

    ret = criu_ns_dump(pid, shell_job=True)
    if ret != 0:
        read_log_file(DUMP_LOG)
        sys.exit(ret)

    os.unlink("running")
    fd_m, fd_s = create_pty()
    pid = os.fork()
    if pid == 0:
        os.setsid()
        fd_m.close()
        # since criu-ns takes control of the tty stdin
        os.dup2(fd_s.fileno(), 0)
        ret = criu_ns_restore(shell_job=True)
        if ret != 0:
            read_log_file(RESTORE_LOG)
            sys.exit(ret)
        os._exit(0)

    fd_s.close()
    os.waitpid(pid, 0)


def test_dump_and_restore_without_shell_job(restore_detached=False):
    print("Test criu-ns dump and restore with an isolated process"
          "(%d)" % restore_detached)
    check_dumpdir()
    pid = create_isolated_dumpee()
    ret = criu_ns_dump(pid)
    if ret != 0:
        read_log_file(DUMP_LOG)
        sys.exit(ret)

    if not restore_detached:
        os.unlink("running")

    pid = os.fork()
    if pid == 0:
        os.setsid()
        ret = criu_ns_restore(restore_detached=restore_detached)
        if ret != 0:
            read_log_file(RESTORE_LOG)
            sys.exit(ret)
        os._exit(0)

    os.waitpid(pid, 0)


def test_dump_and_restore_in_pidns():
    if os.system("grep NSpid /proc/self/status"):
        return

    print("Test criu-ns dump and restore in namespaces")

    def _dump():
        pid = create_isolated_dumpee()
        ret = criu_ns_dump(pid)
        if ret != 0:
            read_log_file(DUMP_LOG)
            sys.exit(ret)

    def _restore():
        ret = criu_ns_restore(restore_detached=True)
        if ret != 0:
            read_log_file(RESTORE_LOG)
            sys.exit(ret)

    def _get_restored_pid():
        restored_pid = 0
        pidfile_path = os.path.join(IMG_DIR, PIDFILE)
        if not os.path.exists(pidfile_path):
            raise FileNotFoundError("pidfile not found")
        with open(pidfile_path, "r") as pidfile:
            restored_pid = pidfile.read().strip()
        return int(restored_pid)

    def _redump():
        global IMG_DIR
        try:
            restored_pid = _get_restored_pid()
        except FileNotFoundError:
            sys.exit(1)
        IMG_DIR = "dumpdir2"
        check_dumpdir(IMG_DIR)
        ret = criu_ns_dump(restored_pid)
        if ret != 0:
            read_log_file(DUMP_LOG)
            sys.exit(ret)

    def _re_restore():
        os.unlink("running")
        ret = criu_ns_restore()
        if ret != 0:
            read_log_file(RESTORE_LOG)
            sys.exit(ret)

    check_dumpdir()
    _dump()
    _restore()
    _redump()
    _re_restore()


def main():
    test_dump_and_restore_with_shell_job()
    test_dump_and_restore_without_shell_job()
    test_dump_and_restore_without_shell_job(restore_detached=True)
    test_dump_and_restore_in_pidns()


if __name__ == "__main__":
    run_task_with_own_pty(main)
