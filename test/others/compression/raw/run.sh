#!/bin/bash

# Verify that entries made entirely of compression raw fallbacks use the
# ordinary uncompressed pagemap representation and still restore correctly.

set -euo pipefail

# shellcheck source=test/others/env.sh
source ../../env.sh

CRIU_CMD=("${CRIU}" --no-default-config)
ZDTM_DIR="../../../zdtm/static"
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RAW_ENTRY_CHECK="${SCRIPT_DIR}/check_raw_entry.py"
PID=""

function fail {
	echo "FAIL: $*"
	exit 1
}

function cleanup {
	if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
		kill -TERM "$PID" 2>/dev/null || true
		for _ in $(seq 1 50); do
			kill -0 "$PID" 2>/dev/null || break
			sleep 0.1
		done
		if kill -0 "$PID" 2>/dev/null; then
			kill -KILL "$PID" 2>/dev/null || true
		fi
	fi
	rm -rf dump-raw-*
}

trap cleanup EXIT

function start_test {
	(
		cd "$ZDTM_DIR" || exit 1
		make compress_pages00.cleanout
		make compress_pages00
		make compress_pages00.pid || exit 1
	)

	PID=$(cat "$ZDTM_DIR/compress_pages00.pid")
	kill -0 "$PID" || fail "Test didn't start"
}

function stop_test {
	(
		cd "$ZDTM_DIR" || exit 1
		make compress_pages00.stop
		grep PASS compress_pages00.out || exit 1
	) || fail "$1: memory content verification failed"
	PID=""
}

function assert_raw_entry {
	local directory="$1"

	PYTHONPATH="${BASE_DIR}/lib${PYTHONPATH:+:${PYTHONPATH}}" \
		python3 "$RAW_ENTRY_CHECK" "$directory" "$PID"
}

function run_mode {
	local name="$1"
	shift
	local imgdir="dump-raw-$name"

	rm -rf "$imgdir"
	mkdir "$imgdir"
	start_test

	"${CRIU_CMD[@]}" dump -D "$imgdir" -o dump.log -t "$PID" -v4 "$@" \
		|| fail "$name: dump failed"
	assert_raw_entry "$imgdir" || fail "$name: raw-entry metadata check failed"
	"${CRIU_CMD[@]}" restore -D "$imgdir" -o restore.log -v4 -d \
		--image-io-mode direct \
		|| fail "$name: restore failed"
	if grep -q "O_DIRECT enabled on pages fd" "$imgdir/restore.log"; then
		grep -q "Restoring delayed VMA I/O with native AIO" \
			"$imgdir/restore.log" || \
			fail "$name: aligned raw ranges did not use direct AIO"
	fi
	stop_test "$name"
}

run_mode page --compress
run_mode region --compress-region=64K

echo "Test PASSED"
