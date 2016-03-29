# Check known fault injections
set -e
source `dirname $0`/criu-lib.sh
prep
./test/zdtm.py run -t zdtm/static/env00 --fault 1 --keep-going --report report -f h || fail
./test/zdtm.py run -t zdtm/static/unlink_fstat00 --fault 2 --keep-going --report report -f h || fail
./test/zdtm.py run -t zdtm/static/maps00 --fault 3 --keep-going --report report -f h || fail
./test/zdtm.py run -t zdtm/static/inotify_irmap --fault 128 --keep-going --pre 2 -f uns || fail
./test/zdtm.py run -t zdtm/static/env00 --fault 129 -f uns || fail
