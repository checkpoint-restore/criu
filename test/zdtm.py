#!/usr/bin/env python
from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals
)

import argparse
import atexit
import datetime
import errno
import fcntl
import glob
import linecache
import mmap
import os
import random
import re
import shutil
import signal
import socket
import stat
import string
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from builtins import input, int, open, range, str, zip

import yaml

import pycriu as crpc
from zdtm.criu_config import criu_config

# File to store content of streamed images
STREAMED_IMG_FILE_NAME = "img.criu"

prev_line = None
uuid = uuid.uuid4()

NON_ROOT_UID = 65534


def alarm(*args):
    print("==== ALARM ====")


def traceit(f, e, a):
    if e == "line":
        lineno = f.f_lineno
        fil = f.f_globals["__file__"]
        if fil.endswith("zdtm.py"):
            global prev_line
            line = linecache.getline(fil, lineno)
            if line == prev_line:
                print("        ...")
            else:
                prev_line = line
                print("+%4d: %s" % (lineno, line.rstrip()))

    return traceit


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


# Report generation

report_dir = None


def init_report(path):
    global report_dir
    report_dir = path
    if not os.access(report_dir, os.F_OK):
        os.makedirs(report_dir)


def add_to_report(path, tgt_name):
    global report_dir
    if report_dir:
        tgt_path = os.path.join(report_dir, tgt_name)
        att = 0
        while os.access(tgt_path, os.F_OK):
            tgt_path = os.path.join(report_dir, tgt_name + ".%d" % att)
            att += 1

        ignore = shutil.ignore_patterns('*.socket')
        if os.path.isdir(path):
            shutil.copytree(path, tgt_path, ignore=ignore)
        else:
            if not os.path.exists(os.path.dirname(tgt_path)):
                os.mkdir(os.path.dirname(tgt_path))
            shutil.copy2(path, tgt_path)


def add_to_output(path):
    global report_dir
    if not report_dir:
        return

    output_path = os.path.join(report_dir, "output")
    with open(path, "r") as fdi, open(output_path, "a") as fdo:
        for line in fdi:
            fdo.write(line)


prev_crash_reports = set(glob.glob("/tmp/zdtm-core-*.txt"))


def check_core_files():
    reports = set(glob.glob("/tmp/zdtm-core-*.txt")) - prev_crash_reports
    if not reports:
        return False

    while subprocess.Popen(r"ps axf | grep 'abrt\.sh'",
                           shell=True).wait() == 0:
        time.sleep(1)

    for i in reports:
        add_to_report(i, os.path.basename(i))
        print_sep(i)
        with open(i, "r") as report:
            print(report.read())
        print_sep(i)

    return True


# Arch we run on
arch = os.uname()[4]

#
# Flavors
#  h -- host, test is run in the same set of namespaces as criu
#  ns -- namespaces, test is run in itw own set of namespaces
#  uns -- user namespace, the same as above plus user namespace
#


class host_flavor:
    def __init__(self, opts):
        self.name = "host"
        self.ns = False
        self.root = None

    def init(self, l_bins, x_bins):
        pass

    def fini(self):
        pass

    @staticmethod
    def clean():
        pass


class ns_flavor:
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
                raise test_fail_exc("Can't find lib %s required by %s" %
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
        raise test_fail_exc("Deps check %s failed" % deps)

    def init(self, l_bins, x_bins):
        subprocess.check_call(
            ["mount", "--make-private", "--bind", ".", self.root])
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
        for d in ns_flavor.__root_dirs:
            p = './' + d
            print('Remove %s' % p)
            if os.access(p, os.F_OK):
                shutil.rmtree('./' + d)

        if os.access('./.constructed', os.F_OK):
            os.unlink('./.constructed')


class userns_flavor(ns_flavor):
    def __init__(self, opts):
        ns_flavor.__init__(self, opts)
        self.name = "userns"
        self.uns = True

    def init(self, l_bins, x_bins):
        # To be able to create roots_yard in CRIU
        os.chmod(".", os.stat(".").st_mode | 0o077)
        ns_flavor.init(self, l_bins, x_bins)

    @staticmethod
    def clean():
        pass


flavors = {'h': host_flavor, 'ns': ns_flavor, 'uns': userns_flavor}
flavors_codes = dict(zip(range(len(flavors)), sorted(flavors.keys())))

#
# Helpers
#


def encode_flav(f):
    return sorted(flavors.keys()).index(f) + 128


def decode_flav(i):
    return flavors_codes.get(i - 128, "unknown")


def tail(path):
    p = subprocess.Popen(['tail', '-n1', path], stdout=subprocess.PIPE)
    out, _ = p.communicate()
    return out.decode()


def rpidfile(path):
    with open(path) as fd:
        return fd.readline().strip()


def wait_pid_die(pid, who, tmo=30):
    stime = 0.1
    while stime < tmo:
        try:
            os.kill(int(pid), 0)
        except OSError as e:
            if e.errno != errno.ESRCH:
                print(e)
            break

        print("Wait for %s(%d) to die for %f" % (who, pid, stime))
        time.sleep(stime)
        stime *= 2
    else:
        subprocess.Popen(["ps", "-p", str(pid)]).wait()
        subprocess.Popen(["ps", "axf", str(pid)]).wait()
        raise test_fail_exc("%s die" % who)


def test_flag(tdesc, flag):
    return flag in tdesc.get('flags', '').split()


#
# Exception thrown when something inside the test goes wrong,
# e.g. test doesn't start, criu returns with non zero code or
# test checks fail
#


class test_fail_exc(Exception):
    def __init__(self, step):
        self.step = step

    def __str__(self):
        return str(self.step)


class test_fail_expected_exc(Exception):
    def __init__(self, cr_action):
        self.cr_action = cr_action


#
# A test from zdtm/ directory.
#


class zdtm_test:
    def __init__(self, name, desc, flavor, freezer, rootless):
        self.__name = name
        self.__desc = desc
        self.__freezer = None
        self.__rootless = rootless
        self.__make_action('cleanout')
        self.__pid = 0
        self.__flavor = flavor
        self.__freezer = freezer
        self._bins = [name]
        self._env = {}
        self._deps = desc.get('deps', [])
        self.auto_reap = True
        self.__timeout = int(self.__desc.get('timeout') or 30)

    def __make_action(self, act, env=None, root=None):
        sys.stdout.flush()  # Not to let make's messages appear before ours
        tpath = self.__name + '.' + act
        s_args = [
            'make', '--no-print-directory', '-C',
            os.path.dirname(tpath),
            os.path.basename(tpath)
        ]

        if env:
            env = dict(os.environ, **env)

        s = subprocess.Popen(
            s_args,
            env=env,
            cwd=root,
            close_fds=True,
            preexec_fn=self.__freezer and self.__freezer.attach or None)
        if act == "pid":
            try_run_hook(self, ["--post-start"])
        if s.wait():
            raise test_fail_exc(str(s_args))

        if self.__freezer:
            self.__freezer.freeze()

    def __pidfile(self):
        return self.__name + '.pid'

    def __wait_task_die(self):
        wait_pid_die(int(self.__pid), self.__name, self.__timeout)

    def __add_wperms(self):
        if os.getuid() != 0:
            return
        # Add write perms for .out and .pid files
        for b in self._bins:
            p = os.path.dirname(b)
            os.chmod(p, os.stat(p).st_mode | 0o222)

    def start(self):
        self.__flavor.init(self._bins, self._deps)

        print("Start test")

        env = self._env
        if not self.__freezer.kernel:
            env['ZDTM_THREAD_BOMB'] = "5"

        if test_flag(self.__desc, 'pre-dump-notify'):
            env['ZDTM_NOTIFY_FDIN'] = "100"
            env['ZDTM_NOTIFY_FDOUT'] = "101"

        if self.__rootless:
            env['ZDTM_ROOTLESS'] = "1"

        if not test_flag(self.__desc, 'suid'):
            # Numbers should match those in criu
            env['ZDTM_UID'] = "18943"
            env['ZDTM_GID'] = "58467"
            env['ZDTM_GROUPS'] = "27495 48244"
            self.__add_wperms()
        else:
            print("Test is SUID")

        if self.__flavor.ns:
            env['ZDTM_NEWNS'] = "1"
            env['ZDTM_ROOT'] = self.__flavor.root
            env['PATH'] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

            if self.__flavor.uns:
                env['ZDTM_USERNS'] = "1"
                self.__add_wperms()
            if os.getenv("GCOV"):
                criu_dir = os.path.dirname(os.getcwd())
                criu_dir_r = "%s%s" % (self.__flavor.root, criu_dir)

                env['ZDTM_CRIU'] = os.path.dirname(os.getcwd())
                subprocess.check_call(["mkdir", "-p", criu_dir_r])

        self.__make_action('pid', env, self.__flavor.root)

        try:
            os.kill(int(self.getpid()), 0)
        except Exception as e:
            raise test_fail_exc("start: %s" % e)

        if not self.static():
            # Wait less than a second to give the test chance to
            # move into some semi-random state
            time.sleep(random.random())

        if self.__flavor.ns:
            # In the case of runc the path specified with the opts.root
            # option is created in /run/runc/ which is inaccessible to
            # unprivileged users. The permissions here are set to test
            # this use case.
            os.chmod(os.path.dirname(self.__flavor.root), 0o700)

    def kill(self, sig=signal.SIGKILL):
        self.__freezer.thaw()
        if self.__pid:
            print("Send the %d signal to  %s" % (sig, self.__pid))
            os.kill(int(self.__pid), sig)
            self.gone(sig == signal.SIGKILL)

        self.__flavor.fini()

    def pre_dump_notify(self):
        env = self._env

        if 'ZDTM_NOTIFY_FDIN' not in env:
            return

        if self.__pid == 0:
            self.getpid()

        notify_fdout_path = "/proc/%s/fd/%s" % (self.__pid,
                                                env['ZDTM_NOTIFY_FDOUT'])
        notify_fdin_path = "/proc/%s/fd/%s" % (self.__pid,
                                               env['ZDTM_NOTIFY_FDIN'])

        print("Send pre-dump notify to %s" % (self.__pid))
        with open(notify_fdout_path, "rb") as fdout:
            with open(notify_fdin_path, "wb") as fdin:
                fdin.write(struct.pack("i", 0))
                fdin.flush()
                print("Wait pre-dump notify reply")
                ret = struct.unpack('i', fdout.read(4))
                print("Completed pre-dump notify with %d" % (ret))

    def stop(self):
        self.__freezer.thaw()
        self.getpid()  # Read the pid from pidfile back
        self.kill(signal.SIGTERM)

        res = tail(self.__name + '.out')
        if 'PASS' not in list(map(lambda s: s.strip(), res.split())):
            if os.access(self.__name + '.out.inprogress', os.F_OK):
                print_sep(self.__name + '.out.inprogress')
                with open(self.__name + '.out.inprogress') as fd:
                    print(fd.read())
                print_sep(self.__name + '.out.inprogress')
            raise test_fail_exc("result check")

    def getpid(self):
        if self.__pid == 0:
            self.__pid = rpidfile(self.__pidfile())

        return self.__pid

    def getname(self):
        return self.__name

    def __getcropts(self):
        opts = self.__desc.get('opts', '').split() + [
            "--pidfile", os.path.realpath(self.__pidfile())
        ]
        if self.__flavor.ns:
            opts += ["--root", self.__flavor.root]
        if test_flag(self.__desc, 'crlib'):
            opts += [
                "--libdir",
                os.path.dirname(os.path.realpath(self.__name)) + '/lib'
            ]
        return opts

    def getdopts(self):
        return self.__getcropts() + self.__freezer.getdopts(
        ) + self.__desc.get('dopts', '').split()

    def getropts(self):
        return self.__getcropts() + self.__freezer.getropts(
        ) + self.__desc.get('ropts', '').split()

    def unlink_pidfile(self):
        self.__pid = 0
        os.unlink(self.__pidfile())

    def gone(self, force=True):
        if not self.auto_reap:
            pid, status = os.waitpid(int(self.__pid), 0)
            if pid != int(self.__pid):
                raise test_fail_exc("kill pid mess")

        self.__wait_task_die()
        self.__pid = 0
        if force:
            os.unlink(self.__pidfile())

    def print_output(self):
        for postfix in ['.out', '.out.inprogress']:
            if os.access(self.__name + postfix, os.R_OK):
                print("Test output: " + "=" * 32)
                with open(self.__name + postfix) as output:
                    print(output.read())
                print(" <<< " + "=" * 32)

    def static(self):
        return self.__name.split('/')[1] == 'static'

    def ns(self):
        return self.__flavor.ns

    def blocking(self):
        return test_flag(self.__desc, 'crfail')

    @staticmethod
    def available():
        if not os.access("umount2", os.X_OK):
            subprocess.check_call(
                ["make", "umount2"], env=dict(os.environ, MAKEFLAGS=""))
        if not os.access("zdtm_ct", os.X_OK):
            subprocess.check_call(
                ["make", "zdtm_ct"], env=dict(os.environ, MAKEFLAGS=""))
        if not os.access("zdtm/lib/libzdtmtst.a", os.F_OK):
            subprocess.check_call(["make", "-C", "zdtm/"])
        if 'rootless' in opts and opts['rootless']:
            return
        subprocess.check_call(
            ["flock", "zdtm_mount_cgroups.lock", "./zdtm_mount_cgroups", str(uuid)])

    @staticmethod
    def cleanup():
        if 'rootless' in opts and opts['rootless']:
            return
        subprocess.check_call(
            ["flock", "zdtm_mount_cgroups.lock", "./zdtm_umount_cgroups", str(uuid)])


def load_module_from_file(name, path):
    if sys.version_info[0] == 3 and sys.version_info[1] >= 5:
        import importlib.util
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    else:
        import imp
        mod = imp.load_source(name, path)
    return mod


class inhfd_test:
    def __init__(self, name, desc, flavor, freezer, rootless):
        if rootless:
            raise test_fail_exc("This kind of test does not currently support rootless mode")
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
                raise test_fail_exc("FDs screwup: %r %r" % (msg, data))
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
            raise test_fail_exc("File descriptors mismatch: %s %s" %
                                (fds, self.__fds))
        i = 0
        for my_file, _ in self.__files:
            msg = self.__get_message(i)
            my_file.write(msg)
            my_file.flush()
            i += 1
        pid, status = os.waitpid(self.__peer_pid, 0)
        with open(self.__name + ".out") as output:
            print(output.read())
        self.__peer_pid = 0
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 42:
            raise test_fail_exc("test failed with %d" % status)

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
            my_file, peer_file = self.__files[i]
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


class groups_test(zdtm_test):
    def __init__(self, name, desc, flavor, freezer, rootless):
        zdtm_test.__init__(self, 'zdtm/lib/groups', desc, flavor, freezer, rootless)
        if flavor.ns:
            self.__real_name = name
            with open(name) as fd:
                self.__subs = list(map(lambda x: x.strip(), fd.readlines()))
            print("Subs:\n%s" % '\n'.join(self.__subs))
        else:
            self.__real_name = ''
            self.__subs = []

        self._bins += self.__subs
        self._deps += get_test_desc('zdtm/lib/groups')['deps']
        self._env = {'ZDTM_TESTS': self.__real_name}

    def __get_start_cmd(self, name):
        tdir = os.path.dirname(name)
        tname = os.path.basename(name)

        s_args = ['make', '--no-print-directory', '-C', tdir]
        subprocess.check_call(s_args + [tname + '.cleanout'])
        s = subprocess.Popen(s_args + ['--dry-run', tname + '.pid'],
                             stdout=subprocess.PIPE)
        out, _ = s.communicate()
        cmd = out.decode().splitlines()[-1].strip()

        return 'cd /' + tdir + ' && ' + cmd

    def start(self):
        if (self.__subs):
            with open(self.__real_name + '.start', 'w') as f:
                for test in self.__subs:
                    cmd = self.__get_start_cmd(test)
                    f.write(cmd + '\n')

            with open(self.__real_name + '.stop', 'w') as f:
                for test in self.__subs:
                    f.write('kill -TERM `cat /%s.pid`\n' % test)

        zdtm_test.start(self)

    def stop(self):
        zdtm_test.stop(self)

        for test in self.__subs:
            res = tail(test + '.out')
            if 'PASS' not in res.split():
                raise test_fail_exc("sub %s result check" % test)


test_classes = {'zdtm': zdtm_test, 'inhfd': inhfd_test, 'groups': groups_test}

#
# CRIU when launched using CLI
#

join_ns_file = '/run/netns/zdtm_netns'


class criu_cli:
    @staticmethod
    def run(action,
            args,
            criu_bin,
            fault=None,
            strace=[],
            preexec=None,
            nowait=False):
        env = dict(
            os.environ,
            ASAN_OPTIONS="log_path=asan.log:disable_coredump=0:detect_leaks=0")

        if fault:
            print("Forcing %s fault" % fault)
            env['CRIU_FAULT'] = fault

        cr = subprocess.Popen(strace +
                              [criu_bin, action, "--no-default-config"] + args,
                              env=env,
                              close_fds=False,
                              preexec_fn=preexec)
        if nowait:
            return cr
        return cr.wait()


class criu_rpc_process:
    def wait(self):
        return self.criu.wait_pid(self.pid)

    def terminate(self):
        os.kill(self.pid, signal.SIGTERM)


class criu_rpc:
    pidfd_store_socket = None

    @staticmethod
    def __set_opts(criu, args, ctx):
        while len(args) != 0:
            arg = args.pop(0)
            if "--verbosity=4" == arg:
                criu.opts.log_level = 4
            elif "--log-file" == arg:
                criu.opts.log_file = args.pop(0)
            elif "--images-dir" == arg:
                criu.opts.images_dir_fd = os.open(args.pop(0), os.O_DIRECTORY)
                ctx['imgd'] = criu.opts.images_dir_fd
            elif "--tree" == arg:
                criu.opts.pid = int(args.pop(0))
            elif "--pidfile" == arg:
                ctx['pidf'] = args.pop(0)
            elif "--timeout" == arg:
                criu.opts.timeout = int(args.pop(0))
            elif "--restore-detached" == arg:
                ctx['rd'] = True  # Set by service by default
            elif "--root" == arg:
                criu.opts.root = args.pop(0)
            elif "--external" == arg:
                criu.opts.external.append(args.pop(0))
            elif "--status-fd" == arg:
                fd = int(args.pop(0))
                os.write(fd, b"\0")
                fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
            elif "--port" == arg:
                criu.opts.ps.port = int(args.pop(0))
            elif "--address" == arg:
                criu.opts.ps.address = args.pop(0)
            elif "--page-server" == arg:
                continue
            elif "--prev-images-dir" == arg:
                criu.opts.parent_img = args.pop(0)
            elif "--pre-dump-mode" == arg:
                key = args.pop(0)
                mode = crpc.rpc.VM_READ
                if key == "splice":
                    mode = crpc.rpc.SPLICE
                criu.opts.pre_dump_mode = mode
            elif "--track-mem" == arg:
                criu.opts.track_mem = True
            elif "--tcp-established" == arg:
                criu.opts.tcp_established = True
            elif "--restore-sibling" == arg:
                criu.opts.rst_sibling = True
            elif "--inherit-fd" == arg:
                inhfd = criu.opts.inherit_fd.add()
                key = args.pop(0)
                fd, key = key.split(":", 1)
                inhfd.fd = int(fd[3:-1])
                inhfd.key = key
            elif "--pidfd-store" == arg:
                if criu_rpc.pidfd_store_socket is None:
                    criu_rpc.pidfd_store_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                criu.opts.pidfd_store_sk = criu_rpc.pidfd_store_socket.fileno()
            elif "--mntns-compat-mode" == arg:
                criu.opts.mntns_compat_mode = True
            else:
                raise test_fail_exc('RPC for %s(%s) required' % (arg, args.pop(0)))

    @staticmethod
    def run(action,
            args,
            criu_bin,
            fault=None,
            strace=[],
            preexec=None,
            nowait=False):
        if fault:
            raise test_fail_exc('RPC and FAULT not supported')
        if strace:
            raise test_fail_exc('RPC and SAT not supported')
        if preexec:
            raise test_fail_exc('RPC and PREEXEC not supported')

        ctx = {}  # Object used to keep info until action is done
        criu = crpc.criu()
        criu.use_binary(criu_bin)
        criu_rpc.__set_opts(criu, args, ctx)
        p = None

        try:
            if action == 'dump':
                criu.dump()
            elif action == 'pre-dump':
                criu.pre_dump()
            elif action == 'restore':
                if 'rd' not in ctx:
                    raise test_fail_exc(
                        'RPC Non-detached restore is impossible')

                res = criu.restore()
                pidf = ctx.get('pidf')
                if pidf:
                    with open(pidf, 'w') as fd:
                        fd.write('%d\n' % res.pid)
            elif action == "page-server":
                res = criu.page_server_chld()
                p = criu_rpc_process()
                p.pid = res.pid
                p.criu = criu
            else:
                raise test_fail_exc('RPC for %s required' % action)
        except crpc.CRIUExceptionExternal as e:
            print("Fail", e)
            ret = -1
        else:
            ret = 0

        imgd = ctx.get('imgd')
        if imgd:
            os.close(imgd)

        if nowait and ret == 0:
            return p

        return ret


class criu:
    def __init__(self, opts):
        self.__test = None
        self.__dump_path = None
        self.__iter = 0
        self.__prev_dump_iter = None
        self.__page_server = bool(opts['page_server'])
        self.__remote_lazy_pages = bool(opts['remote_lazy_pages'])
        self.__lazy_pages = (self.__remote_lazy_pages or
                             bool(opts['lazy_pages']))
        self.__lazy_migrate = bool(opts['lazy_migrate'])
        self.__restore_sibling = bool(opts['sibling'])
        self.__join_ns = bool(opts['join_ns'])
        self.__empty_ns = bool(opts['empty_ns'])
        self.__fault = opts['fault']
        self.__script = opts['script']
        self.__sat = bool(opts['sat'])
        self.__dedup = bool(opts['dedup'])
        self.__mdedup = bool(opts['noauto_dedup'])
        self.__user = bool(opts['user'])
        self.__rootless = bool(opts['rootless'])
        self.__leave_stopped = bool(opts['stop'])
        self.__stream = bool(opts['stream'])
        self.__show_stats = bool(opts['show_stats'])
        self.__lazy_pages_p = None
        self.__page_server_p = None
        self.__dump_process = None
        self.__img_streamer_process = None
        self.__tls = self.__tls_options() if opts['tls'] else []
        self.__criu_bin = opts['criu_bin']
        self.__crit_bin = opts['crit_bin']
        self.__pre_dump_mode = opts['pre_dump_mode']
        self.__mntns_compat_mode = bool(opts['mntns_compat_mode'])

        if opts['rpc']:
            self.__criu = criu_rpc
        elif opts['criu_config']:
            self.__criu = criu_config
        else:
            self.__criu = criu_cli

    def fini(self):
        if self.__lazy_migrate:
            ret = self.__dump_process.wait()
        if self.__lazy_pages_p:
            ret = self.__lazy_pages_p.wait()
            grep_errors(os.path.join(self.__ddir(), "lazy-pages.log"), err=ret)
            self.__lazy_pages_p = None
            if ret:
                raise test_fail_exc("criu lazy-pages exited with %s" % ret)
        if self.__page_server_p:
            ret = self.__page_server_p.wait()
            grep_errors(os.path.join(self.__ddir(), "page-server.log"), err=ret)
            self.__page_server_p = None
            if ret:
                raise test_fail_exc("criu page-server exited with %s" % ret)
        if self.__dump_process:
            ret = self.__dump_process.wait()
            grep_errors(os.path.join(self.__ddir(), "dump.log"), err=ret)
            self.__dump_process = None
            if ret:
                raise test_fail_exc("criu dump exited with %s" % ret)
        if self.__img_streamer_process:
            ret = self.wait_for_criu_image_streamer()
            if ret:
                raise test_fail_exc("criu-image-streamer exited with %s" % ret)

        return

    def logs(self):
        return self.__dump_path

    def set_test(self, test):
        self.__test = test
        self.__dump_path = "dump/" + test.getname() + "/" + test.getpid()
        if os.path.exists(self.__dump_path):
            for i in range(100):
                newpath = self.__dump_path + "." + str(i)
                if not os.path.exists(newpath):
                    os.rename(self.__dump_path, newpath)
                    break
            else:
                raise test_fail_exc("couldn't find dump dir %s" %
                                    self.__dump_path)

        os.makedirs(self.__dump_path)

    def cleanup(self):
        if self.__dump_path:
            print("Removing %s" % self.__dump_path)
            shutil.rmtree(self.__dump_path)

    def __tls_options(self):
        pki_dir = os.path.dirname(os.path.abspath(__file__)) + "/pki"
        return [
            "--tls", "--tls-no-cn-verify", "--tls-key", pki_dir + "/key.pem",
            "--tls-cert", pki_dir + "/cert.pem", "--tls-cacert",
            pki_dir + "/cacert.pem"
        ]

    def __ddir(self):
        return os.path.join(self.__dump_path, "%d" % self.__iter)

    def set_user_id(self):
        # Numbers should match those in zdtm_test
        os.setresgid(58467, 58467, 58467)
        os.setresuid(18943, 18943, 18943)

    def __criu_act(self, action, opts=[], log=None, nowait=False):
        if not log:
            log = action + ".log"

        s_args = ["--log-file", log, "--images-dir", self.__ddir(),
                  "--verbosity=4"] + opts

        with open(os.path.join(self.__ddir(), action + '.cropt'), 'w') as f:
            f.write(' '.join(s_args) + '\n')

        print("Run criu " + action)

        if self.__rootless:
            s_args += ["--unprivileged"]

        strace = []
        if self.__sat:
            fname = os.path.join(self.__ddir(), action + '.strace')
            print_fname(fname, 'strace')
            strace = ["strace", "-o", fname, '-T']
            if action == 'restore':
                strace += ['-f']
                s_args += [
                    '--action-script',
                    os.getcwd() + '/../scripts/fake-restore.sh'
                ]

        if self.__script:
            s_args += ['--action-script', self.__script]

        if action == "restore":
            preexec = None
        else:
            if os.getuid():
                preexec = None
            else:
                preexec = self.__user and self.set_user_id or None

        __ddir = self.__ddir()

        status_fds = None
        if nowait:
            status_fds = os.pipe()
            fd = status_fds[1]
            fdflags = fcntl.fcntl(fd, fcntl.F_GETFD)
            fcntl.fcntl(fd, fcntl.F_SETFD, fdflags & ~fcntl.FD_CLOEXEC)
            s_args += ["--status-fd", str(fd)]

        with open("/proc/sys/kernel/ns_last_pid") as ns_last_pid_fd:
            ns_last_pid = ns_last_pid_fd.read()

        ret = self.__criu.run(action, s_args, self.__criu_bin, self.__fault,
                              strace, preexec, nowait)

        if nowait:
            os.close(status_fds[1])
            if os.read(status_fds[0], 1) != b'\0':
                ret = ret.wait()
                if self.__test.blocking():
                    raise test_fail_expected_exc(action)
                else:
                    raise test_fail_exc("criu %s exited with %s" %
                                        (action, ret))
            os.close(status_fds[0])
            return ret

        grep_errors(os.path.join(__ddir, log))
        if ret != 0:
            if self.__fault and int(self.__fault) < 128:
                try_run_hook(self.__test, ["--fault", action])
                if action == "dump":
                    # create a clean directory for images
                    os.rename(__ddir, __ddir + ".fail")
                    os.mkdir(__ddir)
                    os.chmod(__ddir, 0o777)
                else:
                    # on restore we move only a log file, because we need images
                    os.rename(os.path.join(__ddir, log),
                              os.path.join(__ddir, log + ".fail"))
                # restore ns_last_pid to avoid a case when criu gets
                # PID of one of restored processes.
                with open("/proc/sys/kernel/ns_last_pid", "w+") as fd:
                    fd.write(ns_last_pid)
                # try again without faults
                print("Run criu " + action)
                ret = self.__criu.run(action, s_args, self.__criu_bin, False,
                                      strace, preexec)
                grep_errors(os.path.join(__ddir, log))
                if ret == 0:
                    return
            rst_succeeded = os.access(
                os.path.join(__ddir, "restore-succeeded"), os.F_OK)
            if self.__test.blocking() or (self.__sat and action == 'restore' and
                                          rst_succeeded):
                raise test_fail_expected_exc(action)
            else:
                raise test_fail_exc("CRIU %s" % action)

    def __stats_file(self, action):
        return os.path.join(self.__ddir(), "stats-%s" % action)

    def show_stats(self, action):
        if not self.__show_stats:
            return

        subprocess.Popen([self.__crit_bin, "show",
                          self.__stats_file(action)]).wait()

    def check_pages_counts(self):
        if not os.access(self.__stats_file("dump"), os.R_OK):
            return

        stats_written = -1
        with open(self.__stats_file("dump"), 'rb') as stfile:
            stats = crpc.images.load(stfile)
            stent = stats['entries'][0]['dump']
            stats_written = int(stent['shpages_written']) + int(
                stent['pages_written'])

        if self.__stream:
            self.spawn_criu_image_streamer("extract")
            ret = self.wait_for_criu_image_streamer()
            if ret:
                raise test_fail_exc("criu-image-streamer (extract) exited with %s" % ret)

        real_written = 0
        for f in os.listdir(self.__ddir()):
            if f.startswith('pages-'):
                real_written += os.path.getsize(os.path.join(self.__ddir(), f))

        if self.__stream:
            # make sure the extracted image is not usable.
            os.unlink(os.path.join(self.__ddir(), "inventory.img"))

        r_pages = real_written / mmap.PAGESIZE
        r_off = real_written % mmap.PAGESIZE
        if (stats_written != r_pages) or (r_off != 0):
            print("ERROR: bad page counts, stats = %d real = %d(%d)" %
                  (stats_written, r_pages, r_off))
            raise test_fail_exc("page counts mismatch")

    # action can be "capture", "extract", or "serve"
    def spawn_criu_image_streamer(self, action):
        print("Run criu-image-streamer in {} mode".format(action))

        progress_r, progress_w = os.pipe()
        # We fcntl() on both file descriptors due to some potential differences
        # with python2 and python3.
        fcntl.fcntl(progress_r, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        fcntl.fcntl(progress_w, fcntl.F_SETFD, 0)

        # We use cat because the streamer requires to work with pipes.
        if action == 'capture':
            cmd = ["criu-image-streamer",
                   "--images-dir '{images_dir}'",
                   "--progress-fd {progress_fd}",
                   action,
                   "| cat > {img_file}"]
        else:
            cmd = ["cat {img_file} |",
                   "criu-image-streamer",
                   "--images-dir '{images_dir}'",
                   "--progress-fd {progress_fd}",
                   action]

        log = open(os.path.join(self.__ddir(), "img-streamer.log"), "w")

        # * As we are using a shell pipe command, we want to use pipefail.
        # Otherwise, failures stay unnoticed. For this, we use bash as sh
        # doesn't support that feature.
        # * We use close_fds=False because we want the child to inherit the progress pipe
        p = subprocess.Popen(["bash", "-c", "set -o pipefail; " + " ".join(cmd).format(
            progress_fd=progress_w,
            images_dir=self.__ddir(),
            img_file=os.path.join(self.__ddir(), STREAMED_IMG_FILE_NAME)
        )], stderr=log, close_fds=False)

        log.close()

        os.close(progress_w)
        progress = os.fdopen(progress_r, "r")

        if action == 'serve' or action == 'extract':
            # Consume image statistics
            progress.readline()

        if action == 'capture' or action == 'serve':
            # The streamer socket is ready for consumption once we receive the
            # socket-init message.
            if progress.readline().strip() != "socket-init":
                p.kill()
                raise test_fail_exc(
                    "criu-image-streamer is not starting (exit_code=%d)" % p.wait())

        progress.close()

        self.__img_streamer_process = p

    def wait_for_criu_image_streamer(self):
        ret = self.__img_streamer_process.wait()
        grep_errors(os.path.join(self.__ddir(), "img-streamer.log"))
        self.__img_streamer_process = None
        return ret

    def dump(self, action, opts=[]):
        self.__iter += 1
        os.mkdir(self.__ddir())
        os.chmod(self.__ddir(), 0o777)

        a_opts = ["--tree", self.__test.getpid()]
        if self.__prev_dump_iter:
            a_opts += [
                "--prev-images-dir",
                "../%d" % self.__prev_dump_iter, "--track-mem"
            ]
        self.__prev_dump_iter = self.__iter

        if self.__page_server:
            print("Adding page server")

            ps_opts = ["--port", "12345"] + self.__tls
            if self.__dedup:
                ps_opts += ["--auto-dedup"]

            self.__page_server_p = self.__criu_act("page-server",
                                                   opts=ps_opts,
                                                   nowait=True)
            a_opts += [
                "--page-server", "--address", "127.0.0.1", "--port", "12345"
            ] + self.__tls

        a_opts += self.__test.getdopts()

        if self.__stream:
            self.spawn_criu_image_streamer("capture")
            a_opts += ["--stream"]

        if self.__dedup:
            a_opts += ["--auto-dedup"]

        a_opts += ["--timeout", "10"]

        criu_dir = os.path.dirname(os.getcwd())
        if os.getenv("GCOV"):
            a_opts.append('--external')
            a_opts.append('mnt[%s]:zdtm' % criu_dir)

        if self.__leave_stopped:
            a_opts += ['--leave-stopped']
        if self.__empty_ns:
            a_opts += ['--empty-ns', 'net']
        if self.__pre_dump_mode:
            a_opts += ["--pre-dump-mode", "%s" % self.__pre_dump_mode]

        nowait = False
        if self.__lazy_migrate and action == "dump":
            a_opts += ["--lazy-pages", "--port", "12345"] + self.__tls
            nowait = True
        self.__dump_process = self.__criu_act(action,
                                              opts=a_opts + opts,
                                              nowait=nowait)
        if self.__stream:
            ret = self.wait_for_criu_image_streamer()
            if ret:
                raise test_fail_exc("criu-image-streamer (capture) exited with %d" % ret)

        if self.__mdedup and self.__iter > 1:
            self.__criu_act("dedup", opts=[])

        self.show_stats("dump")
        self.check_pages_counts()

        if self.__leave_stopped:
            pstree_check_stopped(self.__test.getpid())
            pstree_signal(self.__test.getpid(), signal.SIGKILL)

        if self.__page_server_p:
            ret = self.__page_server_p.wait()
            grep_errors(os.path.join(self.__ddir(), "page-server.log"), err=ret)
            self.__page_server_p = None
            if ret:
                raise test_fail_exc("criu page-server exited with %d" % ret)

    def restore(self):
        r_opts = []
        if self.__restore_sibling:
            r_opts = ["--restore-sibling"]
            self.__test.auto_reap = False
        r_opts += self.__test.getropts()
        if self.__join_ns:
            r_opts.append("--join-ns")
            r_opts.append("net:%s" % join_ns_file)
        if self.__empty_ns:
            r_opts += ['--empty-ns', 'net']
            r_opts += ['--action-script', os.getcwd() + '/empty-netns-prep.sh']

        if self.__stream:
            self.spawn_criu_image_streamer("serve")
            r_opts += ["--stream"]

        if self.__dedup:
            r_opts += ["--auto-dedup"]

        self.__prev_dump_iter = None
        criu_dir = os.path.dirname(os.getcwd())
        if os.getenv("GCOV"):
            r_opts.append('--external')
            r_opts.append('mnt[zdtm]:%s' % criu_dir)

        if self.__lazy_pages or self.__lazy_migrate:
            lp_opts = []
            if self.__remote_lazy_pages or self.__lazy_migrate:
                lp_opts += [
                    "--page-server", "--port", "12345", "--address",
                    "127.0.0.1"
                ] + self.__tls

            if self.__remote_lazy_pages:
                ps_opts = [
                    "--pidfile", "ps.pid", "--port", "12345", "--lazy-pages"
                ] + self.__tls
                self.__page_server_p = self.__criu_act("page-server",
                                                       opts=ps_opts,
                                                       nowait=True)
            self.__lazy_pages_p = self.__criu_act("lazy-pages",
                                                  opts=lp_opts,
                                                  nowait=True)
            r_opts += ["--lazy-pages"]

        if self.__mntns_compat_mode:
            r_opts = ['--mntns-compat-mode'] + r_opts

        if self.__leave_stopped:
            r_opts += ['--leave-stopped']

        self.__criu_act("restore", opts=r_opts + ["--restore-detached"])
        if self.__stream:
            ret = self.wait_for_criu_image_streamer()
            if ret:
                raise test_fail_exc("criu-image-streamer (serve) exited with %d" % ret)

        self.show_stats("restore")

        if self.__leave_stopped:
            pstree_check_stopped(self.__test.getpid())
            pstree_signal(self.__test.getpid(), signal.SIGCONT)

    @staticmethod
    def check(feature):
        if feature == 'stream':
            try:
                p = subprocess.Popen(["criu-image-streamer", "--version"])
                return p.wait() == 0
            except Exception:
                return False

        args = ["--no-default-config", "-verbosity=0", "--feature", feature]
        if opts['rootless']:
            args += ["--unprivileged"]

        return criu_cli.run("check", args, opts['criu_bin']) == 0

    @staticmethod
    def available():
        if not os.access(opts['criu_bin'], os.X_OK):
            print("CRIU binary not found at %s" % opts['criu_bin'])
            sys.exit(1)

    def kill(self):
        if self.__lazy_pages_p:
            self.__lazy_pages_p.terminate()
            print("criu lazy-pages exited with %s" %
                  self.__lazy_pages_p.wait())
            grep_errors(os.path.join(self.__ddir(), "lazy-pages.log"), err=True)
            self.__lazy_pages_p = None
        if self.__page_server_p:
            self.__page_server_p.terminate()
            print("criu page-server exited with %s" %
                  self.__page_server_p.wait())
            grep_errors(os.path.join(self.__ddir(), "page-server.log"), err=True)
            self.__page_server_p = None
        if self.__dump_process:
            self.__dump_process.terminate()
            print("criu dump exited with %s" % self.__dump_process.wait())
            grep_errors(os.path.join(self.__ddir(), "dump.log"), err=True)
            self.__dump_process = None
        if self.__img_streamer_process:
            self.__img_streamer_process.terminate()
            ret = self.wait_for_criu_image_streamer()
            print("criu-image-streamer exited with %s" % ret)


def try_run_hook(test, args):
    hname = test.getname() + '.hook'
    if os.access(hname, os.X_OK):
        print("Running %s(%s)" % (hname, ', '.join(args)))
        hook = subprocess.Popen([hname] + args)
        if hook.wait() != 0:
            raise test_fail_exc("hook " + " ".join(args))


#
# Step by step execution
#

do_sbs = False


def init_sbs():
    if sys.stdout.isatty():
        global do_sbs
        do_sbs = True
    else:
        print("Can't do step-by-step in this runtime")


def sbs(what):
    if do_sbs:
        input("Pause %s. Press Enter to continue." % what)


#
# Main testing entity -- dump (probably with pre-dumps) and restore
#
def iter_parm(opt, dflt):
    x = ((opt or str(dflt)) + ":0").split(':')
    return (range(0, int(x[0])), float(x[1]))


def cr(cr_api, test, opts):
    if opts['nocr']:
        return

    cr_api.set_test(test)

    iters = iter_parm(opts['iters'], 1)
    for i in iters[0]:
        pre = iter_parm(opts['pre'], 0)
        for p in pre[0]:
            if opts['snaps']:
                sbs('before snap %d' % p)
                cr_api.dump("dump", opts=["--leave-running", "--track-mem"])
            else:
                sbs('before pre-dump %d' % p)
                cr_api.dump("pre-dump")
                try_run_hook(test, ["--post-pre-dump"])
                test.pre_dump_notify()
            time.sleep(pre[1])

        sbs('before dump')

        os.environ["ZDTM_TEST_PID"] = str(test.getpid())
        if opts['norst']:
            try_run_hook(test, ["--pre-dump"])
            cr_api.dump("dump", opts=["--leave-running"])
        else:
            try_run_hook(test, ["--pre-dump"])
            cr_api.dump("dump")
            if not opts['lazy_migrate']:
                test.gone()
            else:
                test.unlink_pidfile()
            sbs('before restore')
            try_run_hook(test, ["--pre-restore"])
            cr_api.restore()
            os.environ["ZDTM_TEST_PID"] = str(test.getpid())
            os.environ["ZDTM_IMG_DIR"] = cr_api.logs()
            try_run_hook(test, ["--post-restore"])
            sbs('after restore')

        time.sleep(iters[1])


# Additional checks that can be done outside of test process


def get_visible_state(test):
    maps = {}
    files = {}
    mounts = {}

    if not getattr(test, "static", lambda: False)() or \
       not getattr(test, "ns", lambda: False)():
        return ({}, {}, {})

    r = re.compile('^[0-9]+$')
    pids = filter(lambda p: r.match(p),
                  os.listdir("/proc/%s/root/proc/" % test.getpid()))
    for pid in pids:
        files[pid] = set(
            os.listdir("/proc/%s/root/proc/%s/fd" % (test.getpid(), pid)))

        cmaps = [[0, 0, ""]]
        last = 0
        mapsfd = open("/proc/%s/root/proc/%s/maps" % (test.getpid(), pid))
        for mp in mapsfd:
            m = list(map(lambda x: int('0x' + x, 0), mp.split()[0].split('-')))

            m.append(mp.split()[1])

            f = "/proc/%s/root/proc/%s/map_files/%s" % (test.getpid(), pid,
                                                        mp.split()[0])
            if os.access(f, os.F_OK):
                st = os.lstat(f)
                m.append(oct(st.st_mode))

            if cmaps[last][1] == m[0] and cmaps[last][2] == m[2]:
                cmaps[last][1] = m[1]
            else:
                cmaps.append(m)
                last += 1
        mapsfd.close()

        maps[pid] = set(
            map(lambda x: '%x-%x %s' % (x[0], x[1], " ".join(x[2:])), cmaps))

        cmounts = []
        try:
            r = re.compile(
                r"^\S+\s\S+\s\S+\s(\S+)\s(\S+)\s(\S+)\s[^-]*?(shared)?[^-]*?(master)?[^-]*?-"
            )
            with open("/proc/%s/root/proc/%s/mountinfo" %
                      (test.getpid(), pid)) as mountinfo:
                for m in mountinfo:
                    cmounts.append(r.match(m).groups())
        except IOError as e:
            if e.errno != errno.EINVAL:
                raise e
        mounts[pid] = cmounts
    return files, maps, mounts


def has_vsyscall(maps):
    vsyscall = u"ffffffffff600000-ffffffffff601000"
    for i in maps:
        if vsyscall in i:
            return i

    return None


def check_visible_state(test, state, opts):
    new = get_visible_state(test)

    for pid in state[0].keys():
        fnew = new[0][pid]
        fold = state[0][pid]
        if fnew != fold:
            print("%s: Old files lost: %s" % (pid, fold - fnew))
            print("%s: New files appeared: %s" % (pid, fnew - fold))
            raise test_fail_exc("fds compare")

        old_maps = state[1][pid]
        new_maps = new[1][pid]
        if os.getenv("COMPAT_TEST"):
            # the vsyscall vma isn't unmapped from x32 processes
            entry = has_vsyscall(new_maps)
            if entry and has_vsyscall(old_maps) is None:
                new_maps.remove(entry)
        if old_maps != new_maps:
            print("%s: Old maps lost: %s" % (pid, old_maps - new_maps))
            print("%s: New maps appeared: %s" % (pid, new_maps - old_maps))
            if not opts['fault']:  # skip parasite blob
                raise test_fail_exc("maps compare")

        old_mounts = state[2][pid]
        new_mounts = new[2][pid]
        for i in range(len(old_mounts)):
            m = old_mounts.pop(0)
            if m in new_mounts:
                new_mounts.remove(m)
            else:
                old_mounts.append(m)
        if old_mounts or new_mounts:
            print("%s: Old mounts lost: %s" % (pid, old_mounts))
            print("%s: New mounts appeared: %s" % (pid, new_mounts))
            raise test_fail_exc("mounts compare")

    if '--link-remap' in test.getdopts():
        import glob
        link_remap_list = glob.glob(
            os.path.dirname(test.getname()) + '/link_remap*')
        if link_remap_list:
            print("%s: link-remap files left: %s" %
                  (test.getname(), link_remap_list))
            raise test_fail_exc("link remaps left")


class noop_freezer:
    def __init__(self):
        self.kernel = False

    def attach(self):
        pass

    def freeze(self):
        pass

    def thaw(self):
        pass

    def getdopts(self):
        return []

    def getropts(self):
        return []


class cg_freezer2:
    def __init__(self, path, state):
        self.__path = '/sys/fs/cgroup/' + path
        self.__state = state
        self.kernel = True

    def attach(self):
        if not os.access(self.__path, os.F_OK):
            os.makedirs(self.__path)
        with open(self.__path + '/cgroup.procs', 'w') as f:
            f.write('0')

    def __set_state(self, state):
        with open(self.__path + '/cgroup.freeze', 'w') as f:
            f.write(state)

    def freeze(self):
        if self.__state.startswith('f'):
            self.__set_state('1')

    def thaw(self):
        if self.__state.startswith('f'):
            self.__set_state('0')

    def getdopts(self):
        return ['--freeze-cgroup', self.__path, '--manage-cgroups']

    def getropts(self):
        return ['--manage-cgroups']


class cg_freezer:
    def __init__(self, path, state):
        self.__path = '/sys/fs/cgroup/freezer/' + path
        self.__state = state
        self.kernel = True

    def attach(self):
        if not os.access(self.__path, os.F_OK):
            os.makedirs(self.__path)
        with open(self.__path + '/tasks', 'w') as f:
            f.write('0')

    def __set_state(self, state):
        with open(self.__path + '/freezer.state', 'w') as f:
            f.write(state)

    def freeze(self):
        if self.__state.startswith('f'):
            self.__set_state('FROZEN')

    def thaw(self):
        if self.__state.startswith('f'):
            self.__set_state('THAWED')

    def getdopts(self):
        return ['--freeze-cgroup', self.__path, '--manage-cgroups']

    def getropts(self):
        return ['--manage-cgroups']


def get_freezer(desc):
    if not desc:
        return noop_freezer()

    fd = desc.split(':')

    if os.access("/sys/fs/cgroup/user.slice/cgroup.procs", os .F_OK):
        fr = cg_freezer2(path=fd[0], state=fd[1])
    else:
        fr = cg_freezer(path=fd[0], state=fd[1])
    return fr


def cmp_ns(ns1, match, ns2, msg):
    ns1_ino = os.stat(ns1).st_ino
    ns2_ino = os.stat(ns2).st_ino
    if eval("%r %s %r" % (ns1_ino, match, ns2_ino)):
        print("%s match (%r %s %r) fail" % (msg, ns1_ino, match, ns2_ino))
        raise test_fail_exc("%s compare" % msg)


def check_joinns_state(t):
    cmp_ns("/proc/%s/ns/net" % t.getpid(), "!=", join_ns_file, "join-ns")


def pstree_each_pid(root_pid):
    f_children_path = "/proc/{0}/task/{0}/children".format(root_pid)
    child_pids = []
    try:
        with open(f_children_path, "r") as f_children:
            pid_line = f_children.readline().strip(" \n")
            if pid_line:
                child_pids += pid_line.split(" ")
    except Exception as e:
        print("Unable to read /proc/*/children: %s" % e)
        return  # process is dead

    yield root_pid
    for child_pid in child_pids:
        for pid in pstree_each_pid(child_pid):
            yield pid


def is_proc_stopped(pid):
    def get_thread_status(thread_dir):
        try:
            with open(os.path.join(thread_dir, "status")) as f_status:
                for line in f_status.readlines():
                    if line.startswith("State:"):
                        return line.split(":", 1)[1].strip().split(" ")[0]
        except Exception as e:
            print("Unable to read a thread status: %s" % e)
            pass  # process is dead
        return None

    def is_thread_stopped(status):
        return (status is None) or (status == "T") or (status == "Z")

    tasks_dir = "/proc/%s/task" % pid
    thread_dirs = []
    try:
        thread_dirs = os.listdir(tasks_dir)
    except Exception as e:
        print("Unable to read threads: %s" % e)
        pass  # process is dead

    for thread_dir in thread_dirs:
        thread_status = get_thread_status(os.path.join(tasks_dir, thread_dir))
        if not is_thread_stopped(thread_status):
            return False

    if not is_thread_stopped(get_thread_status("/proc/%s" % pid)):
        return False

    return True


def pstree_check_stopped(root_pid):
    for pid in pstree_each_pid(root_pid):
        if not is_proc_stopped(pid):
            raise test_fail_exc("CRIU --leave-stopped %s" % pid)


def pstree_signal(root_pid, signal):
    for pid in pstree_each_pid(root_pid):
        try:
            os.kill(int(pid), signal)
        except Exception as e:
            print("Unable to kill %d: %s" % (pid, e))
            pass  # process is dead


def do_run_test(tname, tdesc, flavs, opts):
    tcname = tname.split('/')[0]
    tclass = test_classes.get(tcname, None)
    if not tclass:
        print("Unknown test class %s" % tcname)
        return

    if opts['report']:
        init_report(opts['report'])
    if opts['sbs']:
        init_sbs()

    fcg = get_freezer(opts['freezecg'])

    for f in flavs:
        print_sep("Run %s in %s" % (tname, f))
        if opts['dry_run']:
            continue
        flav = flavors[f](opts)
        t = tclass(tname, tdesc, flav, fcg, opts['rootless'])
        cr_api = criu(opts)

        try:
            t.start()
            s = get_visible_state(t)
            try:
                cr(cr_api, t, opts)
            except test_fail_expected_exc as e:
                if e.cr_action == "dump":
                    t.stop()
            else:
                check_visible_state(t, s, opts)
                if opts['join_ns']:
                    check_joinns_state(t)
                t.stop()
                cr_api.fini()
                try_run_hook(t, ["--clean"])
                if t.blocking():
                    raise test_fail_exc("unexpected success")
        except test_fail_exc as e:
            print_sep("Test %s FAIL at %s" % (tname, e.step), '#')
            t.print_output()
            t.kill()
            cr_api.kill()
            try_run_hook(t, ["--clean"])
            if cr_api.logs():
                add_to_report(cr_api.logs(),
                              tname.replace('/', '_') + "_" + f + "/images")
            if opts['keep_img'] == 'never':
                cr_api.cleanup()
            # When option --keep-going not specified this exit
            # does two things: exits from subprocess and aborts the
            # main script execution on the 1st error met
            sys.exit(encode_flav(f))
        else:
            if opts['keep_img'] != 'always':
                cr_api.cleanup()
            print_sep("Test %s PASS" % tname)


class Launcher:
    def __init__(self, opts, nr_tests):
        self.__opts = opts
        self.__total = nr_tests
        self.__runtest = 0
        self.__nr = 0
        self.__max = int(opts['parallel'] or 1)
        self.__subs = {}
        self.__fail = False
        self.__file_report = None
        self.__junit_file = None
        self.__junit_test_cases = None
        self.__failed = []
        self.__nr_skip = 0
        if self.__max > 1 and self.__total > 1:
            self.__use_log = True
        elif opts['report']:
            self.__use_log = True
        else:
            self.__use_log = False

        if opts['report'] and (opts['keep_going'] or self.__total == 1):
            global TestSuite, TestCase
            from junit_xml import TestCase, TestSuite
            now = datetime.datetime.now()
            att = 0
            reportname = os.path.join(report_dir, "criu-testreport.tap")
            junitreport = os.path.join(report_dir, "criu-testreport.xml")
            while os.access(reportname, os.F_OK) or os.access(
                    junitreport, os.F_OK):
                reportname = os.path.join(report_dir,
                                          "criu-testreport" + ".%d.tap" % att)
                junitreport = os.path.join(report_dir,
                                           "criu-testreport" + ".%d.xml" % att)
                att += 1

            self.__junit_file = open(junitreport, 'a')
            self.__junit_test_cases = []

            self.__file_report = open(reportname, 'a')
            print(u"TAP version 13", file=self.__file_report)
            print(u"# Hardware architecture: " + arch, file=self.__file_report)
            print(u"# Timestamp: " + now.strftime("%Y-%m-%d %H:%M") +
                  " (GMT+1)",
                  file=self.__file_report)
            print(u"# ", file=self.__file_report)
            print(u"1.." + str(nr_tests), file=self.__file_report)
        with open("/proc/sys/kernel/tainted") as taintfd:
            self.__taint = taintfd.read()
        if int(self.__taint, 0) != 0:
            print("The kernel is tainted: %r" % self.__taint)
            if not opts["ignore_taint"] and os.getenv("ZDTM_IGNORE_TAINT") != '1':
                raise Exception("The kernel is tainted: %r" % self.__taint)

    def __show_progress(self, msg):
        perc = int(self.__nr * 16 / self.__total)
        print("=== Run %d/%d %s %s" %
              (self.__nr, self.__total, '=' * perc + '-' * (16 - perc), msg))

    def skip(self, name, reason):
        print("Skipping %s (%s)" % (name, reason))
        self.__nr += 1
        self.__runtest += 1
        self.__nr_skip += 1

        if self.__junit_test_cases is not None:
            tc = TestCase(name)
            tc.add_skipped_info(reason)
            self.__junit_test_cases.append(tc)
        if self.__file_report:
            testline = u"ok %d - %s # SKIP %s" % (self.__runtest, name, reason)
            print(testline, file=self.__file_report)

    def run_test(self, name, desc, flavor):

        if len(self.__subs) >= self.__max:
            self.wait()

        with open("/proc/sys/kernel/tainted") as taintfd:
            taint = taintfd.read()
        if self.__taint != taint:
            raise Exception("The kernel is tainted: %r (%r)" %
                            (taint, self.__taint))

        '''
        The option --link-remap allows criu to hardlink open files back to the
        file-system on dump (should be removed on restore) and we have a sanity
        check in check_visible_state that they were actually removed at least
        from the root test directory after restore.

        As zdtm runs all tests from the same cwd (e.g.: test/zdtm/static) in
        parallel, hardlinks from one test can mess up with sanity checks of
        another test or even one test can by mistake use hardlinks created by
        another test which is even worse.

        So let's make all tests using --link-remap option non parallel.
        '''
        link_remap_excl = '--link-remap' in desc.get('opts', '').split() + desc.get('dopts', '').split() + desc.get('ropts', '').split()

        if test_flag(desc, 'excl') or link_remap_excl:
            self.wait_all()

        self.__nr += 1
        self.__show_progress(name)

        nd = ('nocr', 'norst', 'pre', 'iters', 'page_server', 'sibling',
              'stop', 'empty_ns', 'fault', 'keep_img', 'report', 'snaps',
              'sat', 'script', 'rpc', 'criu_config', 'lazy_pages', 'join_ns',
              'dedup', 'sbs', 'freezecg', 'user', 'dry_run', 'noauto_dedup',
              'remote_lazy_pages', 'show_stats', 'lazy_migrate', 'stream',
              'tls', 'criu_bin', 'crit_bin', 'pre_dump_mode', 'mntns_compat_mode',
              'rootless')
        arg = repr((name, desc, flavor, {d: self.__opts[d] for d in nd}))

        if self.__use_log:
            logf = name.replace('/', '_') + ".log"
            log = open(logf, "w")
        else:
            logf = None
            log = None

        if opts['rootless'] and os.getuid() == 0:
            os.setgid(NON_ROOT_UID)
            os.setuid(NON_ROOT_UID)
        sub = subprocess.Popen(["./zdtm_ct", "zdtm.py"],
                               env=dict(os.environ, CR_CT_TEST_INFO=arg),
                               stdout=log,
                               stderr=subprocess.STDOUT,
                               close_fds=True)
        self.__subs[sub.pid] = {
            'sub': sub,
            'log': logf,
            'name': name,
            "start": time.time()
        }

        if log:
            log.close()

        if test_flag(desc, 'excl') or link_remap_excl:
            self.wait()

    def __wait_one(self, flags):
        pid = -1
        status = -1
        signal.alarm(10)
        while True:
            try:
                pid, status = os.waitpid(0, flags)
            except OSError as e:
                if e.errno == errno.EINTR:
                    subprocess.Popen(["ps", "axf", "--width", "160"]).wait()
                    continue
                signal.alarm(0)
                raise e
            else:
                break
        signal.alarm(0)

        self.__runtest += 1
        if pid != 0:
            sub = self.__subs.pop(pid)
            # The following wait() is not useful for our domain logic.
            # It's useful for taming warnings in subprocess.Popen.__del__()
            sub['sub'].wait()
            tc = None
            if self.__junit_test_cases is not None:
                tc = TestCase(sub['name'],
                              elapsed_sec=time.time() - sub['start'])
                self.__junit_test_cases.append(tc)
            if status != 0:
                self.__fail = True
                failed_flavor = decode_flav(os.WEXITSTATUS(status))
                self.__failed.append([sub['name'], failed_flavor])
                if self.__file_report:
                    testline = u"not ok %d - %s # flavor %s" % (
                        self.__runtest, sub['name'], failed_flavor)
                    with open(sub['log']) as sublog:
                        output = sublog.read()
                    details = {'output': output}
                    tc.add_error_info(output=output)
                    print(testline, file=self.__file_report)
                    print("%s" % yaml.safe_dump(details,
                                                explicit_start=True,
                                                explicit_end=True,
                                                default_style='|'),
                          file=self.__file_report)
                if sub['log']:
                    add_to_output(sub['log'])
            else:
                if self.__file_report:
                    testline = u"ok %d - %s" % (self.__runtest, sub['name'])
                    print(testline, file=self.__file_report)

            if sub['log']:
                with open(sub['log']) as sublog:
                    print("%s" % sublog.read().encode(
                        'ascii', 'ignore').decode('utf-8'))
                os.unlink(sub['log'])

            return True

        return False

    def __wait_all(self):
        while self.__subs:
            self.__wait_one(0)

    def wait(self):
        self.__wait_one(0)
        while self.__subs:
            if not self.__wait_one(os.WNOHANG):
                break
        if self.__fail and not opts['keep_going']:
            raise test_fail_exc('')

    def wait_all(self):
        self.__wait_all()
        if self.__fail and not opts['keep_going']:
            raise test_fail_exc('')

    def finish(self):
        self.__wait_all()
        if not opts['fault'] and check_core_files():
            self.__fail = True
        if self.__file_report:
            ts = TestSuite(opts['title'], self.__junit_test_cases,
                           os.getenv("NODE_NAME"))
            self.__junit_file.write(TestSuite.to_xml_string([ts]))
            self.__junit_file.close()
            self.__file_report.close()

        if opts['keep_going']:
            if self.__fail:
                print_sep(
                    "%d TEST(S) FAILED (TOTAL %d/SKIPPED %d)" %
                    (len(self.__failed), self.__total, self.__nr_skip), "#")
                for failed in self.__failed:
                    print(" * %s(%s)" % (failed[0], failed[1]))
            else:
                print_sep(
                    "ALL TEST(S) PASSED (TOTAL %d/SKIPPED %d)" %
                    (self.__total, self.__nr_skip), "#")

        if self.__fail:
            print_sep("FAIL", "#")
            sys.exit(1)


def all_tests(opts):
    with open(opts['set'] + '.desc') as fd:
        desc = eval(fd.read())

    files = []
    mask = stat.S_IFREG | stat.S_IXUSR
    for d in os.walk(desc['dir']):
        for f in d[2]:
            fp = os.path.join(d[0], f)
            st = os.lstat(fp)
            if (st.st_mode & mask) != mask:
                continue
            if stat.S_IFMT(st.st_mode) in [stat.S_IFLNK, stat.S_IFSOCK]:
                continue
            files.append(fp)
    excl = list(map(lambda x: os.path.join(desc['dir'], x), desc['exclude']))
    tlist = list(filter(
        lambda x: not x.endswith('.checkskip') and not x.endswith('.hook') and
        x not in excl, map(lambda x: x.strip(), files)))
    return tlist


# Descriptor for abstract test not in list
default_test = {}


def get_test_desc(tname):
    d_path = tname + '.desc'
    if os.access(d_path, os.F_OK) and os.path.getsize(d_path) > 0:
        with open(d_path) as fd:
            return eval(fd.read())

    return default_test


def self_checkskip(tname):
    chs = tname + '.checkskip'
    if os.access(chs, os.X_OK):
        ch = subprocess.Popen([chs])
        return not ch.wait() == 0

    return False


def print_fname(fname, typ):
    print("=[%s]=> %s" % (typ, fname))


def print_sep(title, sep="=", width=80):
    print((" " + title + " ").center(width, sep))


def print_error(line):
    line = line.rstrip()
    print(line.encode('utf-8'))
    if line.endswith('>'):  # combine pie output
        return True
    return False


def grep_errors(fname, err=False):
    first = True
    print_next = False
    before = []
    with open(fname, errors='replace') as fd:
        for line in fd:
            before.append(line)
            if len(before) > 5:
                before.pop(0)
            if "Error" in line or "Warn" in line:
                if first:
                    print_fname(fname, 'log')
                    print_sep("grep Error", "-", 60)
                    first = False
                for i in before:
                    print_next = print_error(i)
                before = []
            else:
                if print_next:
                    print_next = print_error(line)
                    before = []

    # If process failed but there are no errors in log,
    # let's just print the log tail, probably it would
    # be helpful.
    if err and first:
        print_fname(fname, 'log')
        print_sep("grep Error (no)", "-", 60)
        first = False
        for i in before:
            print_next = print_error(i)

    if not first:
        print_sep("ERROR OVER", "-", 60)


def run_tests(opts):
    excl = None
    features = {}

    if opts['pre'] or opts['snaps']:
        if not criu.check("mem_dirty_track"):
            print("Tracking memory is not available")
            return

    if opts['all']:
        torun = all_tests(opts)
        run_all = True
    elif opts['tests']:
        r = re.compile(opts['tests'])
        torun = filter(lambda x: r.match(x), all_tests(opts))
        run_all = True
    elif opts['test']:
        torun = opts['test']
        run_all = False
    elif opts['from']:
        if not os.access(opts['from'], os.R_OK):
            print("No such file")
            return

        with open(opts['from']) as fd:
            torun = map(lambda x: x.strip(), fd)
        opts['keep_going'] = False
        run_all = True
    else:
        print("Specify test with -t <name> or -a")
        return

    torun = list(torun)
    if opts['keep_going'] and len(torun) < 2:
        print(
            "[WARNING] Option --keep-going is more useful when running multiple tests"
        )
        opts['keep_going'] = False

    if opts['exclude']:
        excl = re.compile(".*(" + "|".join(opts['exclude']) + ")")
        print("Compiled exclusion list")

    if opts['report']:
        init_report(opts['report'])

    if opts['parallel'] and opts['freezecg']:
        print("Parallel launch with freezer not supported")
        opts['parallel'] = None

    if opts['join_ns']:
        if subprocess.Popen(["ip", "netns", "add", "zdtm_netns"]).wait():
            raise Exception("Unable to create a network namespace")
        if subprocess.Popen([
                "ip", "netns", "exec", "zdtm_netns", "ip", "link", "set", "up",
                "dev", "lo"
        ]).wait():
            raise Exception("ip link set up dev lo")

    if opts['lazy_pages'] or opts['remote_lazy_pages'] or opts['lazy_migrate']:
        uffd = criu.check("uffd")
        uffd_noncoop = criu.check("uffd-noncoop")
        if not uffd:
            raise Exception(
                "UFFD is not supported, cannot run with --lazy-pages")
        if not uffd_noncoop:
            # Most tests will work with 4.3 - 4.11
            print(
                "[WARNING] Non-cooperative UFFD is missing, some tests might spuriously fail"
            )

    if opts['stream']:
        streamer_dir = os.path.realpath(opts['criu_image_streamer_dir'])
        os.environ['PATH'] = "{}:{}".format(streamer_dir, os.environ['PATH'])
        if not criu.check('stream'):
            raise RuntimeError((
                "Streaming tests need the criu-image-streamer binary to be accessible in the {} directory. " +
                "Specify --criu-image-streamer-dir or modify PATH to provide an alternate location")
                .format(streamer_dir))

    launcher = Launcher(opts, len(torun))
    try:
        for t in torun:
            global arch

            if excl and excl.match(t):
                launcher.skip(t, "exclude")
                continue

            tdesc = get_test_desc(t)
            if tdesc.get('arch', arch) != arch:
                launcher.skip(t, "arch %s" % tdesc['arch'])
                continue

            if test_flag(tdesc, 'reqrst') and opts['norst']:
                launcher.skip(t, "restore stage is required")
                continue

            if run_all and test_flag(tdesc, 'noauto'):
                launcher.skip(t, "manual run only")
                continue

            feat_list = tdesc.get('feature', "")
            for feat in feat_list.split():
                if feat not in features:
                    print("Checking feature %s" % feat)
                    features[feat] = criu.check(feat)

                if not features[feat]:
                    launcher.skip(t, "no %s feature" % feat)
                    feat_list = None
                    break
            if feat_list is None:
                continue

            if self_checkskip(t):
                launcher.skip(t, "checkskip failed")
                continue

            if opts['user']:
                if test_flag(tdesc, 'suid'):
                    launcher.skip(t, "suid test in user mode")
                    continue
                if test_flag(tdesc, 'nouser'):
                    launcher.skip(t, "criu root prio needed")
                    continue

            if opts['join_ns']:
                if test_flag(tdesc, 'samens'):
                    launcher.skip(t, "samens test in the same namespace")
                    continue

            if opts['lazy_pages'] or opts['remote_lazy_pages'] or opts[
                    'lazy_migrate']:
                if test_flag(tdesc, 'nolazy'):
                    launcher.skip(t, "lazy pages are not supported")
                    continue

            if opts['remote_lazy_pages']:
                if test_flag(tdesc, 'noremotelazy'):
                    launcher.skip(t, "remote lazy pages are not supported")
                    continue

            test_flavs = tdesc.get('flavor', 'h ns uns').split()
            opts_flavs = (opts['flavor'] or 'h,ns,uns').split(',')
            if opts_flavs != ['best']:
                run_flavs = set(test_flavs) & set(opts_flavs)
            else:
                run_flavs = set([test_flavs.pop()])
            if not criu.check("userns"):
                run_flavs -= set(['uns'])
            if opts['user']:
                # FIXME -- probably uns will make sense
                run_flavs -= set(['ns', 'uns'])

            # remove ns and uns flavor in join_ns
            if opts['join_ns']:
                run_flavs -= set(['ns', 'uns'])
            if opts['empty_ns']:
                run_flavs -= set(['h'])

            if run_flavs:
                launcher.run_test(t, tdesc, run_flavs)
            else:
                launcher.skip(t, "no flavors")
    finally:
        launcher.finish()
        if opts['join_ns']:
            subprocess.Popen(["ip", "netns", "delete", "zdtm_netns"]).wait()


sti_fmt = "%-40s%-10s%s"


def show_test_info(t):
    tdesc = get_test_desc(t)
    flavs = tdesc.get('flavor', '')
    return sti_fmt % (t, flavs, tdesc.get('flags', ''))


def list_tests(opts):
    tlist = all_tests(opts)
    if opts['info']:
        print(sti_fmt % ('Name', 'Flavors', 'Flags'))
        tlist = map(lambda x: show_test_info(x), tlist)
    print('\n'.join(tlist))


class group:
    def __init__(self, tname, tdesc):
        self.__tests = [tname]
        self.__desc = tdesc
        self.__deps = set()

    def __is_mergeable_desc(self, desc):
        # For now make it full match
        if self.__desc.get('flags') != desc.get('flags'):
            return False
        if self.__desc.get('flavor') != desc.get('flavor'):
            return False
        if self.__desc.get('arch') != desc.get('arch'):
            return False
        if self.__desc.get('opts') != desc.get('opts'):
            return False
        if self.__desc.get('feature') != desc.get('feature'):
            return False
        return True

    def merge(self, tname, tdesc):
        if not self.__is_mergeable_desc(tdesc):
            return False

        self.__deps |= set(tdesc.get('deps', []))
        self.__tests.append(tname)
        return True

    def size(self):
        return len(self.__tests)

    # common method to write a "meta" auxiliary script (hook/checkskip)
    # which will call all tests' scripts in turn
    def __dump_meta(self, fname, ext):
        scripts = filter(lambda names: os.access(names[1], os.X_OK),
                         map(lambda test: (test, test + ext), self.__tests))
        if scripts:
            f = open(fname + ext, "w")
            f.write("#!/bin/sh -e\n")

            for test, script in scripts:
                f.write("echo 'Running %s for %s'\n" % (ext, test))
                f.write('%s "$@"\n' % script)

            f.write("echo 'All %s scripts OK'\n" % ext)
            f.close()
            os.chmod(fname + ext, 0o700)

    def dump(self, fname):
        f = open(fname, "w")
        for t in self.__tests:
            f.write(t + '\n')
        f.close()
        os.chmod(fname, 0o700)

        if len(self.__desc) or len(self.__deps):
            f = open(fname + '.desc', "w")
            if len(self.__deps):
                self.__desc['deps'] = list(self.__deps)
            f.write(repr(self.__desc))
            f.close()

        # write "meta" .checkskip and .hook scripts
        self.__dump_meta(fname, '.checkskip')
        self.__dump_meta(fname, '.hook')


def group_tests(cli_opts):
    excl = None
    groups = []
    pend_groups = []
    maxs = int(cli_opts['max_size'])

    if not os.access("groups", os.F_OK):
        os.mkdir("groups")

    tlist = all_tests(cli_opts)
    random.shuffle(tlist)
    if cli_opts['exclude']:
        excl = re.compile(".*(" + "|".join(cli_opts['exclude']) + ")")
        print("Compiled exclusion list")

    for t in tlist:
        if excl and excl.match(t):
            continue

        td = get_test_desc(t)

        for g in pend_groups:
            if g.merge(t, td):
                if g.size() == maxs:
                    pend_groups.remove(g)
                    groups.append(g)
                break
        else:
            g = group(t, td)
            pend_groups.append(g)

    groups += pend_groups

    nr = 0
    suf = cli_opts['name'] or 'group'

    for g in groups:
        if maxs > 1 and g.size() == 1:  # Not much point in group test for this
            continue

        fn = os.path.join("groups", "%s.%d" % (suf, nr))
        g.dump(fn)
        nr += 1

    print("Generated %d group(s)" % nr)


def clean_stuff(opts):
    print("Cleaning %s" % opts['what'])
    if opts['what'] == 'nsroot':
        for f in flavors:
            f = flavors[f]
            f.clean()


def set_nr_hugepages(nr):
    try:
        orig_hugepages = 0
        with open("/proc/sys/vm/nr_hugepages", "r") as f:
            orig_hugepages = int(f.read())
        with open("/proc/sys/vm/nr_hugepages", "w") as f:
            f.write("{}\n".format(nr))
        return orig_hugepages
    except PermissionError as err:
        # EACCES is expected when running as non-root, otherwise re-raise the exception.
        if err.errno != errno.EACCES or os.getuid() == 0:
            raise
    except OSError as err:
        if err.errno != errno.EOPNOTSUPP:
            raise

    return 0


def get_cli_args():
    """
    Parse command-line arguments
    """
    p = argparse.ArgumentParser("CRIU test suite")
    p.add_argument("--debug",
                   help="Print what's being executed",
                   action='store_true')
    p.add_argument("--set", help="Which set of tests to use", default='zdtm')

    sp = p.add_subparsers(help="Use --help for list of actions")

    rp = sp.add_parser("run", help="Run test(s)")
    rp.set_defaults(action=run_tests)
    rp.add_argument("-a", "--all", action='store_true')
    rp.add_argument("-t", "--test", help="Test name", action='append')
    rp.add_argument("-T", "--tests", help="Regexp")
    rp.add_argument("-F", "--from", help="From file")
    rp.add_argument("-f", "--flavor", help="Flavor to run")
    rp.add_argument("-x",
                    "--exclude",
                    help="Exclude tests from --all run",
                    action='append')

    rp.add_argument("--sibling",
                    help="Restore tests as siblings",
                    action='store_true')
    rp.add_argument("--join-ns",
                    help="Restore tests and join existing namespace",
                    action='store_true')
    rp.add_argument("--empty-ns",
                    help="Restore tests in empty net namespace",
                    action='store_true')
    rp.add_argument("--pre", help="Do some pre-dumps before dump (n[:pause])")
    rp.add_argument("--snaps",
                    help="Instead of pre-dumps do full dumps",
                    action='store_true')
    rp.add_argument("--dedup",
                    help="Auto-deduplicate images on iterations",
                    action='store_true')
    rp.add_argument("--noauto-dedup",
                    help="Manual deduplicate images on iterations",
                    action='store_true')
    rp.add_argument("--nocr",
                    help="Do not CR anything, just check test works",
                    action='store_true')
    rp.add_argument("--norst",
                    help="Don't restore tasks, leave them running after dump",
                    action='store_true')
    rp.add_argument("--stop",
                    help="Check that --leave-stopped option stops ps tree.",
                    action='store_true')
    rp.add_argument("--iters",
                    help="Do CR cycle several times before check (n[:pause])")
    rp.add_argument("--fault", help="Test fault injection")
    rp.add_argument(
        "--sat",
        help="Generate criu strace-s for sat tool (restore is fake, images are kept)",
        action='store_true')
    rp.add_argument(
        "--sbs",
        help="Do step-by-step execution, asking user for keypress to continue",
        action='store_true')
    rp.add_argument("--freezecg", help="Use freeze cgroup (path:state)")
    rp.add_argument("--user", help="Run CRIU as regular user",
                    action='store_true')
    rp.add_argument(
        "--rootless",
        help="Run CRIU rootless (uid!=0) (needs CAP_CHECKPOINT_RESTORE)",
        action='store_true')
    rp.add_argument("--rpc",
                    help="Run CRIU via RPC rather than CLI",
                    action='store_true')

    rp.add_argument("--criu-config",
                    help="Use config file to set CRIU options",
                    action='store_true')
    rp.add_argument("--page-server",
                    help="Use page server dump",
                    action='store_true')
    rp.add_argument("--stream",
                    help="Use criu-image-streamer",
                    action='store_true')
    rp.add_argument("-p", "--parallel", help="Run test in parallel")
    rp.add_argument("--dry-run",
                    help="Don't run tests, just pretend to",
                    action='store_true')
    rp.add_argument("--script", help="Add script to get notified by criu")
    rp.add_argument("-k",
                    "--keep-img",
                    help="Whether or not to keep images after test",
                    choices=['always', 'never', 'failed'],
                    default='failed')
    rp.add_argument("--report", help="Generate summary report in directory")
    rp.add_argument("--keep-going",
                    help="Keep running tests in spite of failures",
                    action='store_true')
    rp.add_argument("--ignore-taint",
                    help="Don't care about a non-zero kernel taint flag",
                    action='store_true')
    rp.add_argument("--lazy-pages",
                    help="restore pages on demand",
                    action='store_true')
    rp.add_argument("--lazy-migrate",
                    help="restore pages on demand",
                    action='store_true')
    rp.add_argument("--remote-lazy-pages",
                    help="simulate lazy migration",
                    action='store_true')
    rp.add_argument("--tls", help="use TLS for migration", action='store_true')
    rp.add_argument("--title", help="A test suite title", default="criu")
    rp.add_argument("--show-stats",
                    help="Show criu statistics",
                    action='store_true')
    rp.add_argument("--criu-bin",
                    help="Path to criu binary",
                    default='../criu/criu')
    rp.add_argument("--crit-bin",
                    help="Path to crit binary",
                    default='../crit/crit')
    rp.add_argument("--criu-image-streamer-dir",
                    help="Directory where the criu-image-streamer binary is located",
                    default="../../criu-image-streamer")
    rp.add_argument("--pre-dump-mode",
                    help="Use splice or read mode of pre-dumping",
                    choices=['splice', 'read'],
                    default='splice')
    rp.add_argument("--mntns-compat-mode",
                    help="Use old compat mounts restore engine",
                    action='store_true')

    lp = sp.add_parser("list", help="List tests")
    lp.set_defaults(action=list_tests)
    lp.add_argument('-i',
                    '--info',
                    help="Show more info about tests",
                    action='store_true')

    gp = sp.add_parser("group", help="Generate groups")
    gp.set_defaults(action=group_tests)
    gp.add_argument("-m", "--max-size",
                    help="Maximum number of tests in group")
    gp.add_argument("-n", "--name", help="Common name for group tests")
    gp.add_argument("-x",
                    "--exclude",
                    help="Exclude tests from --all run",
                    action='append')

    cp = sp.add_parser("clean", help="Clean something")
    cp.set_defaults(action=clean_stuff)
    cp.add_argument("what", choices=['nsroot'])

    return vars(p.parse_args())


def waitpid_and_rip_zombies(pid):
    """
    Collect this namespace's zombies
    """
    while True:
        wpid, status = os.wait()
        if wpid == pid:
            if os.WIFEXITED(status):
                return os.WEXITSTATUS(status)
            return 1


def fork_zdtm():
    """
    Fork here, since we're new pidns init and are supposed to
    collect this namespace's zombies
    """
    if 'CR_CT_TEST_INFO' in os.environ:
        status = 0
        pid = os.fork()
        if pid == 0:
            tinfo = eval(os.environ['CR_CT_TEST_INFO'])
            do_run_test(tinfo[0], tinfo[1], tinfo[2], tinfo[3])
        else:
            status = waitpid_and_rip_zombies(pid)
        sys.exit(status)


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    signal.signal(signal.SIGALRM, alarm)
    fork_zdtm()
    opts = get_cli_args()
    if opts.get('sat', False):
        opts['keep_img'] = 'always'

    if opts['debug']:
        sys.settrace(traceit)

    if opts['action'] == 'run':
        criu.available()
    for tst in test_classes.values():
        tst.available()

    orig_hugepages = set_nr_hugepages(20)
    opts['action'](opts)
    set_nr_hugepages(orig_hugepages)

    for tst in test_classes.values():
        tst.cleanup()
