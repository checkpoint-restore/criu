# Check lazy-pages
set -e
source `dirname $0`/criu-lib.sh
prep
./test/zdtm.py run --all --keep-going --report report --parallel 4 --lazy-pages || fail
