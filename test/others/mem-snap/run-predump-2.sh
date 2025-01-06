#!/bin/bash

source ../env.sh || exit 1

function fail {
	echo "$@"
	exit 1
}
set -x

IMGDIR="dump/"

rm -rf "$IMGDIR"
mkdir "$IMGDIR"

function launch_test {
	echo "Launching test"
	cd ../../zdtm/static/
	make cleanout
	make maps04
	make maps04.pid || fail "Can't start test"
	PID=$(cat maps04.pid)
	kill -0 $PID || fail "Test didn't start"
	cd -
}

function stop_test {
	wtime=1
	cd ../../zdtm/static/
	make maps04.stop
	fgrep PASS maps04.out || fail "Test failed"
	echo "OK"
}

launch_test

echo "Taking plain dump"

mkdir "$IMGDIR/dump-1/"
${CRIU} dump -D "$IMGDIR/dump-1/" -o dump.log -t ${PID} -v4 || fail "Fail to dump"

sleep 1
echo "Restore to check it works"
${CRIU} restore -D "${IMGDIR}/dump-1/" -o restore.log -d -v4 || fail "Fail to restore server"

stop_test


launch_test

echo "Taking pre and plain dumps"

echo "Pre-dump"
mkdir "$IMGDIR/dump-2/"
mkdir "$IMGDIR/dump-2/pre/"
${CRIU} pre-dump -D "$IMGDIR/dump-2/pre/" -o dump.log -t ${PID} -v4 || fail "Fail to pre-dump"

echo "Plain dump"
mkdir "$IMGDIR/dump-2/plain/"
${CRIU} dump -D "$IMGDIR/dump-2/plain/" -o dump.log -t ${PID} -v4 --prev-images-dir=../pre/ --track-mem || fail "Fail to dump"

sleep 1
echo "Restore"
${CRIU} restore -D "${IMGDIR}/dump-2/plain/" -o restore.log -d -v4 || fail "Fail to restore server"

stop_test
