# Check pre-dump

source `dirname $0`/criu-lib.sh &&
prep &&
mkdir -p test/dump &&
mount -t tmpfs dump test/dump &&
make -C test -j 4 'ZDTM_ARGS=-P -i 3 -C' zdtm &&
make -C test -j 4 'ZDTM_ARGS=-p -P -i 3 -C' zdtm && # + page server
true || fail
