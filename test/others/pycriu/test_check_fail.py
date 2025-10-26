#!/usr/bin/env python3
import os
import sys

# Add ../../../lib so we can import pycriu
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "../../../lib"))
if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)

import pycriu  # noqa: E402

def main():
    socket_path = os.path.join(SCRIPT_DIR, "build", "criu_service.socket")

    criu = pycriu.criu()
    criu.use_sk(socket_path)

    # Intentionally set only log_file (no images/work dir) to ensure check() fails
    criu.opts.log_file = "check.log"

    try:
        criu.check()
    except Exception:
        print("PASS")
        return 0

    print("FAIL: check() did not fail when log_file is set without images/work dir")
    return 1

if __name__ == "__main__":
    sys.exit(main())
