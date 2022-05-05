#!/bin/bash

# Check lazy-pages
set -e
source `dirname $0`/criu-lib.sh
prep

source `dirname $0`/criu-lazy-common.sh

# lazy restore from images
./test/zdtm.py run --all --keep-going --report report --parallel 4 \
	       --lazy-pages $LAZY_EXCLUDE || fail

# During pre-dump + lazy-pages we leave VM_NOHUGEPAGE set
LAZY_EXCLUDE="$LAZY_EXCLUDE -x maps02 -x maps09 -x maps10"

# lazy restore from images with pre-dumps
./test/zdtm.py run --all --keep-going --report report --parallel 4 \
	       --lazy-pages --pre 2 $LAZY_EXCLUDE || fail
