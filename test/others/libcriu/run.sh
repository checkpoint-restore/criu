#!/bin/bash

set -x
source ../env.sh || exit 1

echo "== Clean"
make clean
make libcriu
rm -rf wdir

echo "== Prepare"
mkdir -p wdir/i/

echo "== Run tests"
export LD_LIBRARY_PATH=.
export PATH="`dirname ${BASH_SOURCE[0]}`/../../../criu:$PATH"

RESULT=0

function run_test {
	echo "== Build $1"
	if ! make $1; then
		echo "FAIL build $1"
		echo "** Output of $1/test.log"
		cat wdir/i/$1/test.log
		echo "---------------"
		if [ -f wdir/i/$1/dump.log ]; then
			echo "** Contents of dump.log"
			cat wdir/i/$1/dump.log
			echo "---------------"
		fi
		if [ -f wdir/i/$1/restore.log ]; then
			echo "** Contents of restore.log"
			cat wdir/i/$1/restore.log
			echo "---------------"
		fi
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
if [ "$(uname -m)" == "x86_64" ]; then
	# Skip this on aarch64 as aarch64 has no dirty page tracking
	run_test test_iters
fi
run_test test_errno

echo "== Tests done"
make libcriu_clean
[ $RESULT -eq 0 ] && echo "Success" || echo "FAIL"
exit $RESULT
