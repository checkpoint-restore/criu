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
    build_dir = os.path.join(SCRIPT_DIR, "build")
    socket_path = os.path.join(build_dir, "criu_service.socket")
    os.makedirs(build_dir, exist_ok=True)

    # Open a directory FD to use as work_dir_fd (prefer O_PATH if available)
    flags = getattr(os, "O_PATH", 0) or os.O_RDONLY
    fd = os.open(build_dir, flags)

    criu = pycriu.criu()
    criu.use_sk(socket_path)

    criu.opts.work_dir_fd = fd
    criu.opts.log_file = "check.log"
    criu.opts.log_level = 4

    try:
        criu.check()
    except Exception as e:
        print(f"FAIL: {e}")
        return 1
    finally:
        try:
            os.close(fd)
        except Exception:
            pass

    print("PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
