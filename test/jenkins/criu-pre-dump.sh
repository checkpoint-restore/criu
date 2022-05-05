#!/bin/bash

# Check 3 pre-dump-s before dump (with and w/o page server)
set -e
source `dirname $0`/criu-lib.sh
prep
mount_tmpfs_to_dump
# FIXME: https://github.com/checkpoint-restore/criu/issues/1868
./test/zdtm.py run --all --keep-going --report report --parallel 4 --pre 3 -x 'maps04' -x 'maps09' -x 'maps10' || fail
./test/zdtm.py run --all --keep-going --report report --parallel 4 --pre 3 --page-server -x 'maps04' -x 'maps09' -x 'maps10' || fail
