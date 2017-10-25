#!/bin/bash
# Check known fault injections
set -e
source `dirname $0`/criu-lib.sh
prep
./test/zdtm.py run -t zdtm/static/env00 --fault 1 --keep-going --report report -f h || fail
./test/zdtm.py run -t zdtm/static/unlink_fstat00 --fault 2 --keep-going --report report -f h || fail
./test/zdtm.py run -t zdtm/static/maps00 --fault 3 --keep-going --report report -f h || fail
./test/zdtm.py run -t zdtm/static/inotify_irmap --fault 128 --keep-going --pre 2 -f uns || fail
./test/zdtm.py run -t zdtm/static/env00 --fault 129 -f uns || fail
./test/zdtm.py run -t zdtm/transition/fork --fault 130 -f h || fail
./test/zdtm.py run -t zdtm/static/vdso01 --fault 127 || fail
./test/zdtm.py run -t zdtm/static/vdso-proxy --fault 127 --iters 3 || fail

./test/zdtm.py run -t zdtm/static/mntns_ghost --fault 2 --keep-going --report report || fail
./test/zdtm.py run -t zdtm/static/mntns_ghost --fault 4 --keep-going --report report || fail

./test/zdtm.py run -t zdtm/static/mntns_ghost --fault 6 --report report || fail
./test/zdtm.py run -t zdtm/static/mntns_link_remap --fault 6 --report report || fail
./test/zdtm.py run -t zdtm/static/unlink_fstat03 --fault 6 --report report || fail

./test/zdtm.py run -t zdtm/static/env00 --fault 5 --keep-going --report report || fail
./test/zdtm.py run -t zdtm/static/maps04 --fault 131 --keep-going --report report --pre 2:1 || fail
./test/zdtm.py run -t zdtm/transition/maps008 --fault 131 --keep-going --report report --pre 2:1 || fail
./test/zdtm.py run -t zdtm/static/maps01 --fault 132 -f h || fail
