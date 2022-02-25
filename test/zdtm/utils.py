"""
Helper functions reused across modules.
"""
from __future__ import unicode_literals

import errno
import os
import subprocess
import sys
import time
from builtins import int, open, range, str, zip

from .exceptions import TestFailException
from .host_flavor import HostFlavor
from .ns_flavor import NsFlavor
from .userns_flavor import UserNsFlavor

# Flavors
#  h -- host, test is run in the same set of namespaces as criu
#  ns -- namespaces, test is run in itw own set of namespaces
#  uns -- user namespace, the same as above plus user namespace

flavors = {'h': HostFlavor, 'ns': NsFlavor, 'uns': UserNsFlavor}

flavors_codes = dict(zip(range(len(flavors)), sorted(flavors.keys())))


def try_run_hook(test, args):
    hname = test.getname() + '.hook'
    if os.access(hname, os.X_OK):
        print("Running %s(%s)" % (hname, ', '.join(args)))
        hook = subprocess.Popen([hname] + args)
        if hook.wait() != 0:
            raise TestFailException("hook " + " ".join(args))


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
        raise TestFailException("%s die" % who)


def test_flag(tdesc, flag):
    return flag in tdesc.get('flags', '').split()


def tail(path):
    p = subprocess.Popen(['tail', '-n1', path], stdout=subprocess.PIPE)
    out, _ = p.communicate()
    return out.decode()


def print_sep(title, sep="=", width=80):
    print((" " + title + " ").center(width, sep))


def encode_flav(f):
    return sorted(flavors.keys()).index(f) + 128


def decode_flav(i):
    return flavors_codes.get(i - 128, "unknown")


def rpidfile(path):
    with open(path) as fd:
        return fd.readline().strip()


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


# Descriptor for abstract test not in list
default_test = {}


def get_test_desc(tname):
    d_path = tname + '.desc'
    if os.access(d_path, os.F_OK) and os.path.getsize(d_path) > 0:
        with open(d_path) as fd:
            return eval(fd.read())

    return default_test
