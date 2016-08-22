# Check --leave-stopped option
set -e
source `dirname $0`/criu-lib.sh
prep
./test/zdtm.py run -t zdtm/transition/fork --stop --iter 3 || fail
