#!/usr/bin/env python3
import os
import sys

# Add ../../../lib so we can import pycriu
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "../../../lib"))
if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)

import pycriu  # noqa: E402

def _log_path(images_dir, log_file):
    return log_file if os.path.isabs(log_file) else os.path.join(images_dir, log_file)

def main():
    build_dir = os.path.join(SCRIPT_DIR, "build")
    socket_path = os.path.join(build_dir, "criu_service.socket")

    criu = pycriu.criu()
    criu.use_sk(socket_path)

    criu.opts.images_dir = build_dir
    criu.opts.log_file = "check.log"
    criu.opts.log_level = 4

    try:
        criu.check()
    except Exception as e:
        lp = _log_path(build_dir, criu.opts.log_file)
        msg = f"FAIL: {e} ({'see log: ' + lp if os.path.exists(lp) else 'no log found'})"
        print(msg)
        return 1

    lp = _log_path(build_dir, criu.opts.log_file)
    if not (os.path.isfile(lp) and os.path.getsize(lp) > 0):
        print(f"FAIL: log file missing or empty: {lp}")
        return 1

    print("PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
