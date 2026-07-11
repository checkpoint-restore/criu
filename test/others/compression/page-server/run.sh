#!/bin/bash

# Compression is a dump-client setting carried by page-server wire commands.
# A page server must reject local compression settings instead of silently
# changing how ordinary PS_IOV_ADD_F payloads are stored.

set -euo pipefail

# shellcheck source=test/others/env.sh
source ../../env.sh

LOG="page-server-options.$$.log"

function cleanup {
	rm -f "$LOG"
}

trap cleanup EXIT

function fail {
	echo "FAIL: $*"
	exit 1
}

function check_rejected {
	local name="$1"
	shift
	local status

	rm -f "$LOG"
	set +e
	timeout --signal=KILL 5 "${CRIU}" page-server --no-default-config \
		-D . -o "$LOG" --port 54321 "$@"
	status=$?
	set -e

	if [ "$status" -ne 1 ]; then
		fail "$name returned $status instead of rejecting the option"
	fi
	grep -q "compression options apply to the dump client" "$LOG" || \
		fail "$name did not report the page-server compression error"
}

function check_invalid_region {
	local value="$1"
	local status

	rm -f "$LOG"
	set +e
	timeout --foreground --kill-after=1s 5s \
		"${CRIU}" page-server --no-default-config -D . \
		--port 54321 --compress-region="$value" > "$LOG" 2>&1
	status=$?
	set -e

	if [ "$status" -ne 1 ]; then
		fail "malformed region '$value' returned $status"
	fi
	grep -q "Invalid --compress-region" "$LOG" || \
		fail "malformed region '$value' was not rejected by its parser"
}

function check_invalid_threads {
	local value="$1"
	local status

	rm -f "$LOG"
	set +e
	timeout --foreground --kill-after=1s 5s \
		"${CRIU}" page-server --no-default-config -D . --port 54321 \
		--decompress-threads="$value" > "$LOG" 2>&1
	status=$?
	set -e

	if [ "$status" -ne 1 ]; then
		fail "malformed decompression thread count '$value' returned $status"
	fi
	grep -q "Invalid --decompress-threads" "$LOG" || \
		fail "malformed decompression thread count '$value' was not rejected"
}

function check_valid_threads {
	local value="$1"
	local port="$2"
	local status

	rm -f "$LOG"
	set +e
	timeout --foreground --kill-after=1s 2s \
		"${CRIU}" page-server --no-default-config -D . --port "$port" \
		--decompress-threads="$value" > "$LOG" 2>&1
	status=$?
	set -e

	# The option parses; the server waits for connections until the
	# timeout ends it.
	if [ "$status" -ne 124 ] && [ "$status" -ne 137 ]; then
		fail "valid decompression thread count '$value' returned $status"
	fi
	if grep -q "Invalid --decompress-threads" "$LOG"; then
		fail "valid decompression thread count '$value' was rejected"
	fi
}

check_rejected compress --compress
check_rejected acceleration --compress-acceleration 2
check_rejected region --compress-region 64K
check_invalid_region 64Kjunk
check_invalid_region 64MgarbageK
check_invalid_region 64KB
check_invalid_region -64K
check_invalid_region 18446744073709551616K
check_invalid_threads ""
# Check both special values: 0 selects automatic concurrency and 1, the default, is serial per request.
check_valid_threads 0 54322
check_valid_threads 1 54323

echo "Test PASSED"
