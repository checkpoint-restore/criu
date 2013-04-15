#!/bin/bash

NRSNAP=${1:-3}
SPAUSE=${2:-4}

function fail {
	echo "$@"
	exit 1
}
set -x

CRTOOLS="../../crtools"
IMGDIR="dump/"

rm -rf "$IMGDIR"
mkdir "$IMGDIR"

echo "Launching test"
cd ../zdtm/live/static/
make cleanout
make mem-touch
make mem-touch.pid || fail "Can't start test"
PID=$(cat mem-touch.pid)
kill -0 $PID || fail "Test didn't start"
cd -

echo "Making $NRSNAP snapshots"

for SNAP in $(seq 1 $NRSNAP); do
	sleep $SPAUSE
	mkdir "$IMGDIR/$SNAP/"
	if [ $SNAP -eq 1 ] ; then
		# First snapshot -- no parent, keep running
		args="--snapshot -R"
	elif [ $SNAP -eq $NRSNAP ]; then
		# Last snapshot -- has parent, kill afterwards
		args="--snapshot=../$((SNAP - 1))/"
	else
		# Other snapshots -- have parent, keep running
		args="--snapshot=../$((SNAP - 1))/ -R"
	fi

	${CRTOOLS} dump -D "${IMGDIR}/$SNAP/" -o dump.log -t ${PID} $args || fail "Fail to dump"
done

echo "Restoring"
${CRTOOLS} restore -D "${IMGDIR}/$NRSNAP/" -o restore.log -t ${PID} -d -v 4 || fail "Fail to restore server"

cd ../zdtm/live/static/
make mem-touch.out
cat mem-touch.out | fgrep PASS || fail "Test failed"

echo "Test PASSED"
