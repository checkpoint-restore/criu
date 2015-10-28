# Make 3 iteration of dump/restore for each test
set -e
source `dirname $0`/criu-lib.sh
prep
mkdir -p test/dump
mount -t tmpfs dump test/dump
cd test
./zdtm.py run --all --sibling --parallel 4 || fail
