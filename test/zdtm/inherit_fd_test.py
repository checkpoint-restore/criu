"""
The --inherit-fd option cannot be tested using classic zdtm tests as it implies
some data created before restore and passed through criu restore down to the
restored process (descriptor in our case). The InheritFdTest class is used to
implement such tests.
"""
from __future__ import unicode_literals

import fcntl
import os
import random
import signal
import string
import sys
import time
from builtins import open, range

from .exceptions import TestFailException
from .utils import load_module_from_file, wait_pid_die


class InheritFdTest:
    def __init__(self, name, desc, flavor, freezer):
        self.__name = os.path.basename(name)
        print("Load %s" % name)
        self.__fdtyp = load_module_from_file(self.__name, name)
        self.__peer_pid = 0
        self.__files = None
        self.__peer_file_names = []
        self.__dump_opts = []
        self.__messages = {}

    def __get_message(self, i):
        m = self.__messages.get(i, None)
        if not m:
            m = b"".join([
                random.choice(string.ascii_letters).encode() for _ in range(10)
            ]) + b"%06d" % i
        self.__messages[i] = m
        return m

    def start(self):
        self.__files = self.__fdtyp.create_fds()

        # Check FDs returned for inter-connection
        i = 0
        for my_file, peer_file in self.__files:
            msg = self.__get_message(i)
            my_file.write(msg)
            my_file.flush()
            data = peer_file.read(len(msg))
            if data != msg:
                raise TestFailException("FDs screwup: %r %r" % (msg, data))
            i += 1

        start_pipe = os.pipe()
        self.__peer_pid = os.fork()
        if self.__peer_pid == 0:
            os.setsid()

            for _, peer_file in self.__files:
                getattr(self.__fdtyp, "child_prep", lambda fd: None)(peer_file)

            try:
                os.unlink(self.__name + ".out")
            except Exception as e:
                print(e)
            fd = os.open(self.__name + ".out",
                         os.O_WRONLY | os.O_APPEND | os.O_CREAT)
            os.dup2(fd, 1)
            os.dup2(fd, 2)
            os.close(fd)
            fd = os.open("/dev/null", os.O_RDONLY)
            os.dup2(fd, 0)
            for my_file, _ in self.__files:
                my_file.close()
            os.close(start_pipe[0])
            os.close(start_pipe[1])
            i = 0
            for _, peer_file in self.__files:
                msg = self.__get_message(i)
                try:
                    # File pairs naturally block on read() until the write()
                    # happen (or the writer is closed). This is not the case for
                    # regular files, so we loop.
                    data = b''
                    while not data:
                        # In python 2.7, peer_file.read() doesn't call the read
                        # system call if it's read file to the end once. The
                        # next seek allows to workaround this problem.
                        data = os.read(peer_file.fileno(), 16)
                        time.sleep(0.1)
                except Exception as e:
                    print("Unable to read a peer file: %s" % e)
                    sys.exit(1)

                if data != msg:
                    print("%r %r" % (data, msg))
                i += 1
            sys.exit(data == msg and 42 or 2)

        os.close(start_pipe[1])
        os.read(start_pipe[0], 12)
        os.close(start_pipe[0])

        for _, peer_file in self.__files:
            self.__peer_file_names.append(self.__fdtyp.filename(peer_file))
            self.__dump_opts += self.__fdtyp.dump_opts(peer_file)

        self.__fds = set(os.listdir("/proc/%s/fd" % self.__peer_pid))

    def stop(self):
        fds = set(os.listdir("/proc/%s/fd" % self.__peer_pid))
        if fds != self.__fds:
            raise TestFailException("File descriptors mismatch: %s %s" %
                                    (fds, self.__fds))
        i = 0
        for my_file, _ in self.__files:
            msg = self.__get_message(i)
            my_file.write(msg)
            my_file.flush()
            i += 1
        _, status = os.waitpid(self.__peer_pid, 0)
        with open(self.__name + ".out") as output:
            print(output.read())
        self.__peer_pid = 0
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 42:
            raise TestFailException("test failed with %d" % status)

    def kill(self):
        if self.__peer_pid:
            os.kill(self.__peer_pid, signal.SIGKILL)

    def getname(self):
        return self.__name

    def getpid(self):
        return "%s" % self.__peer_pid

    def gone(self, force=True):
        os.waitpid(self.__peer_pid, 0)
        wait_pid_die(self.__peer_pid, self.__name)
        self.__files = None

    def getdopts(self):
        return self.__dump_opts

    def getropts(self):
        self.__files = self.__fdtyp.create_fds()
        ropts = ["--restore-sibling"]
        for i in range(len(self.__files)):
            _, peer_file = self.__files[i]
            fd = peer_file.fileno()
            fdflags = fcntl.fcntl(fd, fcntl.F_GETFD) & ~fcntl.FD_CLOEXEC
            fcntl.fcntl(fd, fcntl.F_SETFD, fdflags)
            peer_file_name = self.__peer_file_names[i]
            ropts.extend(["--inherit-fd", "fd[%d]:%s" % (fd, peer_file_name)])
        self.__peer_file_names = []
        self.__dump_opts = []
        for _, peer_file in self.__files:
            self.__peer_file_names.append(self.__fdtyp.filename(peer_file))
            self.__dump_opts += self.__fdtyp.dump_opts(peer_file)
        return ropts

    def print_output(self):
        pass

    def static(self):
        return True

    def blocking(self):
        return False

    @staticmethod
    def available():
        pass

    @staticmethod
    def cleanup():
        pass
