#!/usr/bin/env python3
#
# Block until the process with the given PID has exited, or exit 1
# after timeout. Uses pidfd_open(2) so the wait wakes the moment the
# tgid transitions out of existence, without polling /proc or kill -0
# (which both treat zombies as still alive).
#
# Usage: pidfd-wait.py <pid> [timeout_seconds]

import os
import select
import sys


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("usage: pidfd-wait.py <pid> [timeout_seconds]", file=sys.stderr)
        return 2

    pid = int(sys.argv[1])
    timeout_s = float(sys.argv[2]) if len(sys.argv) == 3 else 5.0

    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return 0

    poller = select.poll()
    poller.register(fd, select.POLLIN)
    return 0 if poller.poll(int(timeout_s * 1000)) else 1


if __name__ == "__main__":
    sys.exit(main())
