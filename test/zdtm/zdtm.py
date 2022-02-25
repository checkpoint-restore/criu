from __future__ import unicode_literals

import os
import random
import signal
import struct
import subprocess
import sys
import time
import uuid
from builtins import int, open, str

from .exceptions import TestFailException
from .utils import (
    print_sep,
    rpidfile,
    tail,
    test_flag,
    try_run_hook,
    wait_pid_die
)


class ZdtmTest:
    """
    An object representing a test in zdtm/ directory.
    """

    uuid = uuid.uuid4()

    def __init__(self, name, desc, flavor, freezer):
        self.__name = name
        self.__desc = desc
        self.__freezer = None
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
            raise TestFailException(str(s_args))

        if self.__freezer:
            self.__freezer.freeze()

    def __pidfile(self):
        return self.__name + '.pid'

    def __wait_task_die(self):
        wait_pid_die(int(self.__pid), self.__name, self.__timeout)

    def __add_wperms(self):
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
            raise TestFailException("start: %s" % e)

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
            raise TestFailException("result check")

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
                raise TestFailException("kill pid mess")

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
        subprocess.check_call(
            ["flock", "zdtm_mount_cgroups.lock", "./zdtm_mount_cgroups", str(ZdtmTest.uuid)])

    @staticmethod
    def cleanup():
        subprocess.check_call(
            ["flock", "zdtm_mount_cgroups.lock", "./zdtm_umount_cgroups", str(ZdtmTest.uuid)])
