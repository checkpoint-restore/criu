#!/bin/bash

# Check that dump is not destructive
set -e
source `dirname $0`/criu-lib.sh
prep
mount_tmpfs_to_dump
./test/zdtm.py run --all --keep-going --report report --parallel 4 --norst -x 'maps04' -x 'cgroup02' || fail
