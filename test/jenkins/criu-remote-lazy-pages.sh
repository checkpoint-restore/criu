#!/bin/bash

# Check remote-lazy-pages
set -e
source `dirname $0`/criu-lib.sh
prep

source `dirname $0`/criu-lazy-common.sh

# lazy restore from "remote" dump
./test/zdtm.py run --all --keep-going --report report --parallel 4 \
	       --remote-lazy-pages $LAZY_EXCLUDE -x maps04 || fail

# During pre-dump + lazy-pages we leave VM_NOHUGEPAGE set
LAZY_EXCLUDE="$LAZY_EXCLUDE -x maps02"

# lazy restore from "remote" dump with pre-dumps
./test/zdtm.py run --all --keep-going --report report --parallel 4 \
	       --remote-lazy-pages --pre 2 $LAZY_EXCLUDE || fail
