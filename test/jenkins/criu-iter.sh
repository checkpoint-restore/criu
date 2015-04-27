# Make 3 iteration of dump/restore for each test

source `dirname $0`/criu-lib.sh &&
prep &&
mkdir -p test/dump &&
mount -t tmpfs dump test/dump &&
make -C test ZDTM_ARGS="-C -i 3 -x maps04" zdtm &&
true || fail
