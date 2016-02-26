#!/bin/bash

source ../env.sh || exit 1

USEPS=0

if [ "$1" = "-s" ]; then
	echo "Will test via page-server"
	USEPS=1
	shift
fi

NRSNAP=${1:-3}
SPAUSE=${2:-4}
PORT=12345

function fail {
	echo "$@"
	exit 1
}
set -x

IMGDIR="dump/"

rm -rf "$IMGDIR"
mkdir "$IMGDIR"

echo "Launching test"
cd ../../zdtm/static/
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
		args="--track-mem -R"
	elif [ $SNAP -eq $NRSNAP ]; then
		# Last snapshot -- has parent, kill afterwards
		args="--prev-images-dir=../$((SNAP - 1))/ --track-mem --auto-dedup"
	else
		# Other snapshots -- have parent, keep running
		args="--prev-images-dir=../$((SNAP - 1))/ --track-mem -R --auto-dedup"
	fi

	if [ $USEPS -eq 1 ]; then
		${CRIU} page-server -D "${IMGDIR}/$SNAP/" -o ps.log --auto-dedup --port ${PORT} -v4 &
		PS_PID=$!
		ps_args="--page-server --address 127.0.0.1 --port=${PORT}"
	else
		ps_args=""
	fi

	${CRIU} dump -D "${IMGDIR}/$SNAP/" -o dump.log -t ${PID} -v4 $args $ps_args || fail "Fail to dump"
	if [ $USEPS -eq 1 ]; then
		wait $PS_PID
	fi
done

echo "Restoring"
${CRIU} restore -D "${IMGDIR}/$NRSNAP/" -o restore.log --auto-dedup -d -v4 || fail "Fail to restore server"

size_last3=$(du -sh -BK dump/3/pages-*.img | grep -Eo '[0-9]+' | head -1)
size_last2=$(du -sh -BK dump/2/pages-*.img | grep -Eo '[0-9]+' | head -1)
size_last1=$(du -sh -BK dump/1/pages-*.img | grep -Eo '[0-9]+' | head -1)

restore_dedup_ok=0
if [[ $size_last1 -ne 0 || $size_last2 -ne 0 || $size_last3 -ne 0 ]]; then
	restore_dedup_ok=1
fi

cd ../../zdtm/static/
make mem-touch.stop
cat mem-touch.out | fgrep PASS || fail "Test failed"

if [ $restore_dedup_ok -ne 0 ]; then
	fail "Dedup test failed"
fi

echo "Test PASSED"
