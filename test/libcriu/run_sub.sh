#!/bin/bash

source ../env.sh || exit 1

LOOP_PID=0

echo "== Clean"
make clean
rm -rf wdir
rm -f ./libcriu.so.1

echo "== Prepare"
make test_sub || { echo "FAIL"; exit 1; }

mkdir -p wdir/s/
mkdir -p wdir/i/
echo "== Start service"
${CRIU} service -v4 -o service.log --address cs.sk -d --pidfile pidfile -W wdir/s/ || { echo "FAIL"; exit 1; }

echo "== Run test_sub"
ln -s ../../lib/libcriu.so libcriu.so.1
export LD_LIBRARY_PATH=.
export PATH="`dirname ${BASH_SOURCE[0]}`/../../:$PATH"
./test_sub wdir/s/cs.sk wdir/i/

echo "== Stopping service"
kill -TERM $(cat wdir/s/pidfile)
