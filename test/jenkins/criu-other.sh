source `dirname $0`/criu-lib.sh &&
prep &&
make -C test other &&
true || fail
