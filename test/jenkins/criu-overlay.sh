#!/bin/bash

# Make one regular C/R cycle
set -e
source `dirname $0`/criu-lib.sh
prep
mkdir -p test.up test.work
mount -t overlay overlay -olowerdir=test,upperdir=test.up,workdir=test.work test
./test/zdtm.py run --all --keep-going --report report --parallel 4 -x inotify -x mntns_open -x socket -x sk-unix -x unlink -x fsnotify -x fanotify -x ghost || fail
