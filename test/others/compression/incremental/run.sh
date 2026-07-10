#!/bin/bash

# Test incremental checkpoint chains that change compression mode by layer.
#
# Exercise both ways of mixing compressed and uncompressed iterative
# checkpoint images. Readers must use the compression metadata from their
# own pagemap entries, not from the top image inventory.

set -euo pipefail

# shellcheck source=test/others/env.sh
source ../../env.sh

function fail {
	echo "FAIL: $*"
	exit 1
}

set -x

CRIU_CMD=("${CRIU}" --no-default-config)
ZDTM_DIR="../../../zdtm/static"
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
IMAGE_TOOL="${SCRIPT_DIR}/image_tool.py"
PID=""

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
	rm -rf dump-*
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

function run_image_tool {
	PYTHONPATH="${BASE_DIR}/lib${PYTHONPATH:+:${PYTHONPATH}}" \
		python3 "$IMAGE_TOOL" "$@"
}

function assert_inventory_compression {
	local directory="$1"
	local expected_mode="$2"
	local expected_version="$3"

	run_image_tool inventory-compression \
		"$directory" "$expected_mode" "$expected_version"
}

function assert_present_payload {
	local directory="$1"

	run_image_tool present-payload "$directory" "$PID"
}

function toggle_test_page {
	local directory="$1"
	local address_file="$2"

	# Pick the largest present mapping from the preceding image. Toggling its
	# first byte after each pre-dump makes the next layer contain real payload;
	# the second toggle restores the byte expected by the ZDTM workload.
	run_image_tool toggle-page "$directory" "$PID" "$address_file"
}

function validate_compression_mode {
	local chain_name="$1"
	local stage="$2"
	local mode="$3"

	case "$mode" in
	plain | page | region) ;;
	*) fail "$chain_name: unknown $stage compression mode $mode" ;;
	esac
}

function create_checkpoint_layer {
	local chain_name="$1"
	local stage="$2"
	local operation="$3"
	local directory="$4"
	local previous="$5"
	local compression_mode="$6"
	local expected_version="$7"
	local args=("$operation" -D "$directory" -o dump.log -t "$PID" -v4)

	args+=(--track-mem)
	if [ "$operation" = "pre-dump" ]; then
		args+=(-R)
	fi
	if [ -n "$previous" ]; then
		args+=(--prev-images-dir="$previous")
	fi

	case "$compression_mode" in
	page) args+=(--compress) ;;
	region) args+=(--compress-region=64K) ;;
	plain) ;;
	esac

	echo "=== $chain_name: $stage ==="
	mkdir "$directory"
	"${CRIU_CMD[@]}" "${args[@]}" || fail "$chain_name: $stage failed"
	assert_present_payload "$directory" || \
		fail "$chain_name: $stage contains no payload"
	assert_inventory_compression \
		"$directory" "$compression_mode" "$expected_version" || \
		fail "$chain_name: $stage inventory compression state is invalid"
}

function run_chain {
	local name="$1"
	local predump_compress="$2"
	local dump_compress="$3"
	local imgdir="dump-$name"
	local parent_version=2
	local final_version

	validate_compression_mode "$name" "pre-dump" "$predump_compress"
	validate_compression_mode "$name" "final dump" "$dump_compress"

	if [ "$predump_compress" != "plain" ]; then
		parent_version=3
	fi

	final_version=$parent_version
	if [ "$dump_compress" != "plain" ]; then
		final_version=3
	fi

	rm -rf "$imgdir"
	mkdir "$imgdir"

	start_test

	create_checkpoint_layer "$name" "pre-dump 1" pre-dump \
		"$imgdir/1/" "" "$predump_compress" "$parent_version"
	toggle_test_page "$imgdir/1/" "$imgdir/toggle-address" \
		|| fail "$name: unable to modify workload"

	create_checkpoint_layer "$name" "pre-dump 2" pre-dump \
		"$imgdir/2/" "../1/" "$predump_compress" "$parent_version"
	toggle_test_page "$imgdir/2/" "$imgdir/toggle-address" \
		|| fail "$name: unable to restore workload byte"

	create_checkpoint_layer "$name" "final dump" dump \
		"$imgdir/3/" "../2/" "$dump_compress" "$final_version"

	echo "=== $name: restore ==="
	"${CRIU_CMD[@]}" restore -D "$imgdir/3/" -o restore.log -v4 -d \
		|| fail "$name: restore failed"

	stop_test "$name"
	rm -rf "$imgdir"
}

run_chain "plain-parents-compressed-final" plain page
run_chain "compressed-parents-plain-final" page plain
run_chain "plain-parents-region-final" plain region
run_chain "region-parents-plain-final" region plain

echo "Test PASSED"
