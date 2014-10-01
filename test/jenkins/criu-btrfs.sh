# This is a job which is executed on btrfs

source `dirname $0`/criu-lib.sh &&
prep &&
make -C test -j 4 ZDTM_ARGS="-C -x '\(maps04\|mountpoints\|inotify_irmap\)'" zdtm &&
true || fail
