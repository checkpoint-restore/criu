from __future__ import unicode_literals

import os
from builtins import open


class NoopFreezer:
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


class CgroupFreezer:
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


class CgroupFreezer2:
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


def get_freezer(desc):
    if not desc:
        return NoopFreezer()

    fd = desc.split(':')

    if os.access("/sys/fs/cgroup/user.slice/cgroup.procs", os .F_OK):
        fr = CgroupFreezer2(path=fd[0], state=fd[1])
    else:
        fr = CgroupFreezer(path=fd[0], state=fd[1])
    return fr
