#!/bin/bash
#
# Test that truncated pages files are detected during restore of
# premapped VMAs (the process_async_reads() path in pagemap.c).
#
# Uses a parent+child process pair so that COW VMAs get premapped
# during restore, routing page reads through process_async_reads().
#

source ../env.sh || exit 1

function fail {
	echo "$@"
	exit 1
}
set -x

IMGDIR="dump"

rm -rf "$IMGDIR"
mkdir "$IMGDIR"

setsid ./memalloc_fork < /dev/null &> /dev/null &
PID=$!
sleep 1
kill -0 $PID || fail "Test didn't start"

echo "Dumping process tree"
${CRIU} dump -D "$IMGDIR" -o dump.log -t $PID -v4 --shell-job \
	|| fail "Fail to dump"

# In a COW process tree, prepare_cow_vmas() marks the root's matching
# VMAs with VMA_COW_ROOT. These VMAs are then premapped and their page
# data is read via process_async_reads() in pagemap.c (using PR_ASYNC).
#
# The root process always gets the lowest-numbered pages file
# (pages-1.img). Truncating it forces process_async_reads() to hit EOF,
# which — without the fix — causes an infinite loop.
PAGES_FILES=($(find "$IMGDIR" -name "pages-*.img" -type f | sort))
if [ ${#PAGES_FILES[@]} -lt 2 ]; then
	fail "Expected multiple pages files for parent+child dump, got ${#PAGES_FILES[@]}"
fi
# Pick the root's file (first) — its premapped COW VMAs use process_async_reads().
PAGES_FILE="${PAGES_FILES[0]}"

ORIGINAL_SIZE=$(stat -c%s "$PAGES_FILE")
if [ "$ORIGINAL_SIZE" -lt 4096 ]; then
	fail "Root pages file too small to truncate ($ORIGINAL_SIZE bytes)"
fi
TRUNCATE_SIZE=$((ORIGINAL_SIZE / 4))
echo "Truncating $PAGES_FILE from $ORIGINAL_SIZE to $TRUNCATE_SIZE bytes"
truncate -s "$TRUNCATE_SIZE" "$PAGES_FILE"

echo "Restoring"
set +e
timeout -k 5 30 ${CRIU} restore -D "$IMGDIR" -o restore.log -v4 --shell-job
RESTORE_EXIT=$?
set -e

# Clean up any restored processes
kill -9 $PID 2>/dev/null || true
wait $PID 2>/dev/null || true

if [ $RESTORE_EXIT -eq 124 ] || [ $RESTORE_EXIT -eq 137 ]; then
	fail "Restore timed out (infinite loop — missing EOF check?)"
fi

if [ $RESTORE_EXIT -eq 0 ]; then
	fail "Restore succeeded unexpectedly"
fi

echo PASS
