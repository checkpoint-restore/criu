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

echo "Making $NRSNAP pre-dumps"

for SNAP in $(seq 1 $NRSNAP); do
	sleep $SPAUSE
	mkdir "$IMGDIR/$SNAP/"
	if [ $SNAP -eq 1 ] ; then
		# First pre-dump
		cmd="pre-dump"
		args="--track-mem -R"
	elif [ $SNAP -eq $NRSNAP ]; then
		# Last dump
		cmd="dump"
		args="--prev-images-dir=../$((SNAP - 1))/ --track-mem"
	else
		# Other pre-dumps
		cmd="pre-dump"
		args="--prev-images-dir=../$((SNAP - 1))/ --track-mem -R"
	fi

	if [ $USEPS -eq 1 ]; then
		${CRIU} page-server -D "${IMGDIR}/$SNAP/" -o ps.log --port ${PORT} -v4 &
		PS_PID=$!
		ps_args="--page-server --address 127.0.0.1 --port=${PORT}"
	else
		ps_args=""
	fi

	${CRIU} $cmd -D "${IMGDIR}/$SNAP/" -o dump.log -t ${PID} -v4 $args $ps_args || fail "Fail to dump"
	if [ $USEPS -eq 1 ]; then
		wait $PS_PID
	fi
done

echo "Restoring"
${CRIU} restore -D "${IMGDIR}/$NRSNAP/" -o restore.log -d -v4 || fail "Fail to restore server"

cd ../../zdtm/static/
make mem-touch.stop
cat mem-touch.out | fgrep PASS || fail "Test failed"

echo "Test PASSED"
