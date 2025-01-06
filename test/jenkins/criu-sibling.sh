#!/bin/bash

# Make 3 iteration of dump/restore for each test
set -e
source `dirname $0`/criu-lib.sh
prep
mount_tmpfs_to_dump
./test/zdtm.py run --all --keep-going --report report --sibling --parallel 4 -x 'maps04' || fail
