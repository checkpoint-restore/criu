#!/bin/bash

# Check auto-deduplication of pagemaps
set -e
source `dirname $0`/criu-lib.sh
prep
./test/zdtm.py run --all --keep-going --report report --parallel 4 -f h --pre 2 --dedup -x maps04 -x maps007 -x maps09 -x maps10 || fail

# Additionally run these tests as they touch a lot of
# memory and it makes sense to additionally check it
# with delays between iterations
./test/zdtm.py run -t zdtm/transition/maps007 --report report -f h --pre 8:.1 --dedup || fail
./test/zdtm.py run -t zdtm/static/mem-touch   --report report -f h --pre 8:.1 --dedup || fail
./test/zdtm.py run -t zdtm/transition/maps008 --report report -f h --pre 8:.1 --dedup || fail
./test/zdtm.py run -t zdtm/transition/maps007 --report report -f h --pre 8:.1 --noauto-dedup || fail
./test/zdtm.py run -t zdtm/static/mem-touch   --report report -f h --pre 8:.1 --noauto-dedup || fail
