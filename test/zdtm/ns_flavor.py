"""
A namespaces flavor test runs in its own set of namespaces.
"""
from __future__ import unicode_literals

import atexit
import errno
import fcntl
import os
import re
import shutil
import stat
import subprocess
import tempfile
from builtins import open, str

from .exceptions import TestFailException

# Root dir for ns and uns flavors. All tests
# sit in the same dir
tests_root = None


def clean_tests_root():
    global tests_root
    if tests_root and tests_root[0] == os.getpid():
        os.rmdir(os.path.join(tests_root[1], "root"))
        os.rmdir(tests_root[1])


def make_tests_root():
    global tests_root
    if not tests_root:
        tests_root = (os.getpid(), tempfile.mkdtemp("", "criu-root-", "/tmp"))
        atexit.register(clean_tests_root)
        os.mkdir(os.path.join(tests_root[1], "root"))
    os.chmod(tests_root[1], 0o777)
    return os.path.join(tests_root[1], "root")


class NsFlavor:
    __root_dirs = [
        "/bin", "/sbin", "/etc", "/lib", "/lib64", "/dev", "/dev/pts",
        "/dev/net", "/tmp", "/usr", "/proc", "/run"
    ]

    def __init__(self, opts):
        self.name = "ns"
        self.ns = True
        self.uns = False
        self.root = make_tests_root()
        self.root_mounted = False

    def __copy_one(self, fname):
        tfname = self.root + fname
        if not os.access(tfname, os.F_OK):
            # Copying should be atomic as tests can be
            # run in parallel
            try:
                os.makedirs(self.root + os.path.dirname(fname))
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
            dst = tempfile.mktemp(".tso", "",
                                  self.root + os.path.dirname(fname))
            shutil.copy2(fname, dst)
            os.rename(dst, tfname)

    def __copy_libs(self, binary):
        ldd = subprocess.Popen(["ldd", binary], stdout=subprocess.PIPE)
        stdout, _ = ldd.communicate()

        xl = re.compile(
            r'^(linux-gate.so|linux-vdso(64)?.so|not a dynamic|.*\s*ldd\s)')

        # This Mayakovsky-style code gets list of libraries a binary
        # needs minus vdso and gate .so-s
        libs = map(
            lambda x: x[1] == '=>' and x[2] or x[0],
            map(
                lambda x: str(x).split(),
                filter(
                    lambda x: not xl.match(x),
                    map(
                        lambda x: str(x).strip(),
                        filter(lambda x: str(x).startswith('\t'),
                               stdout.decode(
                                   'ascii').splitlines())))))

        for lib in libs:
            if not os.access(lib, os.F_OK):
                raise TestFailException("Can't find lib %s required by %s" %
                                        (lib, binary))
            self.__copy_one(lib)

    def __mknod(self, name, rdev=None):
        name = "/dev/" + name
        if not rdev:
            if not os.access(name, os.F_OK):
                print("Skipping %s at root" % name)
                return
            else:
                rdev = os.stat(name).st_rdev

        name = self.root + name
        os.mknod(name, stat.S_IFCHR, rdev)
        os.chmod(name, 0o666)

    def __construct_root(self):
        for dir in self.__root_dirs:
            os.mkdir(self.root + dir)
            os.chmod(self.root + dir, 0o777)

        for ldir in ["/bin", "/sbin", "/lib", "/lib64"]:
            os.symlink(".." + ldir, self.root + "/usr" + ldir)

        self.__mknod("tty", os.makedev(5, 0))
        self.__mknod("null", os.makedev(1, 3))
        self.__mknod("net/tun")
        self.__mknod("rtc")
        self.__mknod("autofs", os.makedev(10, 235))

    def __copy_deps(self, deps):
        for d in deps.split('|'):
            if os.access(d, os.F_OK):
                self.__copy_one(d)
                self.__copy_libs(d)
                return
        raise TestFailException("Deps check %s failed" % deps)

    def init(self, l_bins, x_bins):
        subprocess.check_call(
            ["mount", "--make-slave", "--bind", ".", self.root])
        self.root_mounted = True

        if not os.access(self.root + "/.constructed", os.F_OK):
            with open(os.path.abspath(__file__)) as o:
                fcntl.flock(o, fcntl.LOCK_EX)
                if not os.access(self.root + "/.constructed", os.F_OK):
                    print("Construct root for %s" % l_bins[0])
                    self.__construct_root()
                    os.mknod(self.root + "/.constructed", stat.S_IFREG | 0o600)

        for b in l_bins:
            self.__copy_libs(b)
        for b in x_bins:
            self.__copy_deps(b)

    def fini(self):
        if self.root_mounted:
            subprocess.check_call(["./umount2", self.root])
            self.root_mounted = False

    @staticmethod
    def clean():
        for d in NsFlavor.__root_dirs:
            p = './' + d
            print('Remove %s' % p)
            if os.access(p, os.F_OK):
                shutil.rmtree('./' + d)

        if os.access('./.constructed', os.F_OK):
            os.unlink('./.constructed')
