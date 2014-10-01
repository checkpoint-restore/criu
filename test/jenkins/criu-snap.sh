# Check snapshots

source `dirname $0`/criu-lib.sh &&
prep &&
mkdir -p test/dump &&
mount -t tmpfs dump test/dump &&
make -C test -j 4 ZDTM_ARGS="-s -i 3 -C -x '\(unlink\|socket-tcp\)'" zdtm &&
true || fail
