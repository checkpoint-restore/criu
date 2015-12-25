# Check known fault injections
set -e
source `dirname $0`/criu-lib.sh
prep
./test//zdtm.py --set inhfd run --all -f h || fail
