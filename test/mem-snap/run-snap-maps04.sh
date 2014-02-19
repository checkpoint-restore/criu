#!/bin/bash

source ../env.sh || exit 1

USEPS=0

if [ "$1" = "-s" ]; then
	echo "Will test via page-server"
	USEPS=1
	shift
fi

NRSNAP=1
SPAUSE=${2:-4}
PORT=12345

function fail {
	echo "$@"
	exit 1
}
set -x

IMGDIR="dump"
CURDIR=${pwd}
if ! mount | fgrep "$CURDIR/$IMGDIR" ; then
	rm -rf "$IMGDIR"
	mkdir "$IMGDIR"

	mount -t tmpfs -o size=1500M,nr_inodes=10k,mode=700 tmpfs $IMGDIR
fi
rm -rf "$IMGDIR/*"

echo "Launching test"
make -C ../zdtm/live/static/ cleanout
make -C ../zdtm/live/static/ maps04
make -C ../zdtm/live/static/ maps04.pid || fail "Can't start test"
PID=$(cat ../zdtm/live/static/maps04.pid)
kill -0 $PID || fail "Test haven't started"

mkdir "$IMGDIR/$NRSNAP/"

if [ $USEPS -eq 1 ] ; then
	${CRIU} page-server -D "${IMGDIR}/$NRSNAP/" -o ps.log --port ${PORT} -d -v4 #&
	PS_PID=$!
	ps_args="--page-server --address 127.0.0.1 --port=${PORT}"
else
	ps_args=""
fi

${CRIU} dump -D "${IMGDIR}/$NRSNAP/" -o dump.log -t ${PID} -v4 $ps_args || fail "Fail to dump"
if [ $USEPS -eq 1 ] ; then
	wait $PS_PID
fi

echo "Restoring"
${CRIU} restore -D "${IMGDIR}/$NRSNAP/" -o restore.log --auto-dedup -d -v4 || fail "Fail to restore"

make -C ../zdtm/live/static/ maps04.out
sleep 1

cat "../zdtm/live/static/maps04.out" | fgrep PASS || fail "Test failed"

size=$(du -sh -BK  dump/1/pages-*.img | grep -Eo '[0-9]+' | head -1)
if [ $size -ne 0 ] ; then
	fail "Size not null"
fi

echo "Test PASSED"
