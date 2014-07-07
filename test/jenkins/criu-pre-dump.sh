# Check pre-dump

source `dirname $0`/criu-lib.sh &&
prep &&
mkdir -p test/dump &&
mount -t tmpfs dump test/dump &&
make -C test -j 4 'ZDTM_ARGS=-P -i 3 -C' &&
true || fail
