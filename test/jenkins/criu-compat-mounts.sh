#!/bin/bash

# Make one regular C/R cycle with mount-v2 disabled
set -e
source `dirname $0`/criu-lib.sh
prep
FAIL=0
./test/zdtm.py run --all --mntns-compat-mode --keep-going --report report --parallel 4 || FAIL=$?

# Make device-external mounts test
EXTRA_OPTS=--mntns-compat-mode make -C test/others/mnt-ext-dev/ run || FAIL=$?

if [ $FAIL -ne 0 ]; then
	fail
fi
