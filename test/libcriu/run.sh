#!/bin/bash

source ../env.sh || exit 1

echo "== Clean"
make clean
rm -rf wdir
rm -f ./libcriu.so.1

echo "== Prepare"
mkdir -p wdir/s/
mkdir wdir/i/
echo "== Start service"
${CRIU} service -v4 -o service.log --address cs.sk -d --pidfile pidfile -W wdir/s/ || { echo "FAIL service start"; exit 1; }

echo "== Run tests"
ln -s ../../lib/libcriu.so libcriu.so.1
export LD_LIBRARY_PATH=.
export PATH="`dirname ${BASH_SOURCE[0]}`/../../:$PATH"

RESULT=0

function run_test {
	echo "== Build $1"
	if ! make $1; then
		echo "FAIL build $1"
		RESULT=1;
	else
		echo "== Test $1"
		mkdir wdir/i/$1/
		if ! ./$1 wdir/s/cs.sk wdir/i/$1/; then
			echo "$1: FAIL"
			RESULT=1
		fi
	fi
}

run_test test_sub
run_test test_self
run_test test_notify
run_test test_iters
run_test test_errno

echo "== Stopping service"
kill -TERM $(cat wdir/s/pidfile)
[ $RESULT -eq 0 ] && echo "Success" || echo "FAIL"
exit $RESULT
