#!/bin/bash

source ../env.sh || exit 1

function fail {
	echo "$@"
	exit 1
}
set -x

IMGDIR="dump"

rm -rf "$IMGDIR"
mkdir "$IMGDIR"

setsid ./memalloc < /dev/null &> /dev/null &
PID=$!
sleep 1
kill -0 $PID || fail "Test didn't start"

echo "Dumping"
${CRIU} dump -D "$IMGDIR" -o dump.log -t $PID -v4 --shell-job || fail "Fail to dump"

PAGES_FILE=$(find "$IMGDIR" -name "pages-*.img" -type f | head -1)
if [ -z "$PAGES_FILE" ]; then
	fail "No pages file found"
fi

ORIGINAL_SIZE=$(stat -c%s "$PAGES_FILE")
if [ "$ORIGINAL_SIZE" -lt 8192 ]; then
	fail "Pages file too small ($ORIGINAL_SIZE bytes)"
fi

TRUNCATE_SIZE=$((ORIGINAL_SIZE / 4))
echo "Truncating $PAGES_FILE from $ORIGINAL_SIZE to $TRUNCATE_SIZE bytes"
truncate -s "$TRUNCATE_SIZE" "$PAGES_FILE"

echo "Restoring"
set +e
timeout -k 5 30 ${CRIU} restore -D "$IMGDIR" -o restore.log -v4 --shell-job
RESTORE_EXIT=$?
set -e

if [ $RESTORE_EXIT -eq 124 ] || [ $RESTORE_EXIT -eq 137 ]; then
	fail "Restore timed out (infinite loop — missing EOF check?)"
fi

if [ $RESTORE_EXIT -eq 0 ]; then
	fail "Restore succeeded unexpectedly"
fi

echo PASS
