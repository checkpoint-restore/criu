# Check known fault injections
set -e
source `dirname $0`/criu-lib.sh
prep
./zdtm.py run -t zdtm/live/static/env00 --fault 1 --report report -f h || fail
./zdtm.py run -t zdtm/live/static/unlink_fstat00 --fault 2 --report report -f h || fail
