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

    try:
        criu.check()
    except Exception as e:
        print(f"FAIL: {e}")
        return 1

    print("PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
