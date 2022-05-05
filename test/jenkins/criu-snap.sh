#!/bin/bash

# Check snapshots
set -e
source `dirname $0`/criu-lib.sh
prep
mount_tmpfs_to_dump
./test/zdtm.py run --all --keep-going --report report --parallel 4 --pre 3 --snaps -x 'maps04' -x 'maps09' -x 'maps10' || fail
./test/zdtm.py run --all --keep-going --report report --parallel 4 --pre 3 --snaps --page-server -x 'maps04' -x 'maps09' -x 'maps10' || fail
