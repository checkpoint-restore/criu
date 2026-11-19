#!/usr/bin/env python3
import os
import signal
import sys
import tempfile
import time

# Add ../../../lib so we can import pycriu
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "../../../lib"))
if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)

import pycriu  # noqa: E402


def worker_stdio(fake_criu, inherit_stdio, daemon):
    """
    Start fake_criu the way pycriu starts criu swrk and return what its
    fds 0-2 refer to: (st_dev, st_ino), or None for a closed fd.
    """
    criu = pycriu.criu()
    criu.use_binary(fake_criu, inherit_stdio=inherit_stdio)
    comm = criu._comm
    comm.connect(daemon)
    try:
        # Look at the exec'ed binary, not the forked Python child.
        for _ in range(500):
            with open("/proc/%d/cmdline" % comm.swrk, "rb") as f:
                if f.read().split(b"\0")[0] == b"sleep":
                    break
            time.sleep(0.01)
        else:
            raise Exception("fake criu did not start")
        fds = []
        for fd in (0, 1, 2):
            try:
                st = os.stat("/proc/%d/fd/%d" % (comm.swrk, fd))
                fds.append((st.st_dev, st.st_ino))
            except FileNotFoundError:
                fds.append(None)
        return fds
    finally:
        os.kill(comm.swrk, signal.SIGKILL)
        comm.disconnect()


def check(fake_criu):
    ours = []
    for fd in (0, 1, 2):
        st = os.fstat(fd)
        ours.append((st.st_dev, st.st_ino))
    # daemon=True is the self-dump path, which also calls setsid().
    for daemon in (False, True):
        if worker_stdio(fake_criu, False, daemon) != [None, None, None]:
            return "criu got stdio without inherit_stdio (daemon=%s)" % daemon
        if worker_stdio(fake_criu, True, daemon) != ours:
            return "criu did not inherit stdio (daemon=%s)" % daemon
    return None


def main():
    with tempfile.TemporaryDirectory() as tmp:
        fake_criu = os.path.join(tmp, "criu")
        with open(fake_criu, "w") as f:
            f.write("#!/bin/sh\nexec sleep 30\n")
        os.chmod(fake_criu, 0o755)

        # Use stdio that nothing else shares, so that /dev/null or a
        # closed fd cannot pass for an inherited one.
        saved = [os.dup(fd) for fd in (0, 1, 2)]
        r, w = os.pipe()
        os.dup2(r, 0)
        os.dup2(w, 1)
        os.dup2(w, 2)
        try:
            err = check(fake_criu)
        finally:
            for fd in (0, 1, 2):
                os.dup2(saved[fd], fd)
                os.close(saved[fd])
            os.close(r)
            os.close(w)

    if err:
        print("FAIL: %s" % err)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
