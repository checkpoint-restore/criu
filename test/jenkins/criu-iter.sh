# Make 3 iteration of dump/restore for each test

source `dirname $0`/criu-lib.sh &&
prep &&
make -C test -j 4 ZDTM_ARGS="-C -i 3" &&
true || fail
