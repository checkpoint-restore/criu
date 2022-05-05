#!/bin/bash

# Check lazy-pages
set -e
source `dirname $0`/criu-lib.sh
prep

source `dirname $0`/criu-lazy-common.sh

# These tests seem to require complete separation of dump and restore namespaces
LAZY_MIGRATE_EXCLUDE="-x fifo_loop -x file_locks -x ptrace_sig -x overmount_file  -x file_lease -x cr_veth -x fifo -x overmount_sock -x unlink_largefile -x socket_udp-corked -x netns_sub_veth"

# lazy restore from images
./test/zdtm.py run --all --keep-going --report report --parallel 4 -f uns \
	       --lazy-migrate $LAZY_EXCLUDE $LAZY_MIGRATE_EXCLUDE || fail

# During pre-dump + lazy-pages we leave VM_NOHUGEPAGE set
LAZY_EXCLUDE="$LAZY_EXCLUDE -x maps02 -x maps09 -x maps10"

# lazy restore from images with pre-dumps
./test/zdtm.py run --all --keep-going --report report --parallel 4 -f uns \
	       --lazy-migrate --pre 2 $LAZY_EXCLUDE $LAZY_MIGRATE_EXCLUDE || fail
