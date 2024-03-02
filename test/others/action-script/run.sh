#!/bin/bash

set -ebm

# shellcheck source=test/others/env.sh
source ../env.sh || exit 1

SELFDIR="$(dirname "$(readlink -f "$0")")"
SCRIPT="$SELFDIR/action-script.sh"
IMGDIR="$SELFDIR/img-dir-$$"

rm -rf "$IMGDIR"
mkdir "$IMGDIR"

trap "cleanup" QUIT TERM INT HUP EXIT

# shellcheck disable=SC2317
# https://github.com/koalaman/shellcheck/issues/2660
function cleanup()
{
	if [[ -n "$PID" ]]; then
		kill -9 "$PID"
	fi
}

PID=$(../loop)
if ! $CRIU dump -v4 -o dump.log -t "$PID" -D "$IMGDIR" --action-script "$SCRIPT"; then
	echo "Failed to checkpoint process $PID"
	cat dump.log
	kill -9 "$PID"
	exit 1
fi

if ! $CRIU restore -v4 -o restore.log -D "$IMGDIR" -d --pidfile test.pidfile --action-script "$SCRIPT"; then
	echo "CRIU restore failed"
	echo FAIL
	exit 1
fi

PID=$(cat "$IMGDIR"/test.pidfile)

found_missing_file=false
hooks=("pre-dump" "post-dump" "pre-restore" "pre-resume" "post-restore" "post-resume")

for hook in "${hooks[@]}"
do
	if [ ! -e "$IMGDIR/action-hook-$hook" ]; then
		echo "ERROR: action-hook-$hook does not exist"
		found_missing_file=true
	fi
done

if [ "$found_missing_file" = true ]; then
	exit 1
fi

echo PASS

rm -rf "$IMGDIR"
exit 0
