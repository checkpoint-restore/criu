#!/bin/bash

set -x
source ../env.sh || exit 1

echo "== Clean"
make clean
rm -rf wdir
rm -f ./libcriu.so.1

echo "== Prepare"
mkdir -p wdir/i/

echo "== Run tests"
ln -s ../../../../criu/lib/c/libcriu.so libcriu.so.1
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
		if ! setsid ./$1 ${CRIU} wdir/i/$1/ < /dev/null &>> wdir/i/$1/test.log; then
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

echo "== Tests done"
unlink libcriu.so.1
[ $RESULT -eq 0 ] && echo "Success" || echo "FAIL"
exit $RESULT
