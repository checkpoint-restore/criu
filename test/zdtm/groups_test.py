from __future__ import unicode_literals

import os
import subprocess
from builtins import open

from .exceptions import TestFailException
from .utils import get_test_desc, tail
from .zdtm import ZdtmTest


class GroupsTest(ZdtmTest):
    def __init__(self, name, desc, flavor, freezer):
        ZdtmTest.__init__(self, 'zdtm/lib/groups', desc, flavor, freezer)
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
        s.wait()

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

        ZdtmTest.start(self)

    def stop(self):
        ZdtmTest.stop(self)

        for test in self.__subs:
            res = tail(test + '.out')
            if 'PASS' not in res.split():
                raise TestFailException("sub %s result check" % test)
