#!/bin/sh

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CRIU="$ROOT/criu/criu"
PLUGIN_BUILD_DIR="$ROOT/plugins/cuda"
MOCK_DIR="$ROOT/test/cuda-checkpoint"
WORK_DIR=$(mktemp -d)
PLUGIN_DIR="$WORK_DIR/plugins"
EMPTY_PLUGIN_DIR="$WORK_DIR/empty-plugins"
EMPTY_PATH="$WORK_DIR/empty-path"
TARGET_PID=

cleanup()
{
	if [ -n "$TARGET_PID" ]; then
		kill "$TARGET_PID" 2>/dev/null || true
		wait "$TARGET_PID" 2>/dev/null || true
	fi
	rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

run_success()
{
	RUN_DESCRIPTION=$1
	shift

	set +e
	timeout 30s "$@"
	RUN_STATUS=$?
	set -e

	if [ "$RUN_STATUS" -eq 0 ]; then
		return
	fi
	if [ "$RUN_STATUS" -eq 124 ]; then
		echo "$RUN_DESCRIPTION timed out"
	else
		echo "$RUN_DESCRIPTION failed with status $RUN_STATUS"
	fi
	exit 1
}

make -C "$ROOT" cuda_plugin
make -C "$MOCK_DIR"

mkdir "$PLUGIN_DIR" "$EMPTY_PLUGIN_DIR" "$EMPTY_PATH"
cp "$PLUGIN_BUILD_DIR/cuda_plugin.so" "$PLUGIN_DIR/cuda_plugin.so"

# A CPU-only restore has no CUDA inventory requirement. The plugin must disable
# itself before probing either backend. Make the Driver API query and every CLI
# invocation fail so any accidental probe makes the restore fail.
NO_CUDA_IMAGES="$WORK_DIR/no-cuda-images"
mkdir "$NO_CUDA_IMAGES"
sleep 300 &
TARGET_PID=$!
run_success "CPU-only dump" "$CRIU" dump \
	--no-default-config \
	--tree "$TARGET_PID" \
	--images-dir "$NO_CUDA_IMAGES" \
	--log-file dump.log \
	--verbosity=4 \
	--libdir "$EMPTY_PLUGIN_DIR" \
	--shell-job
wait "$TARGET_PID" 2>/dev/null || true

CLI_MARKER="$NO_CUDA_IMAGES/cli-invoked"
run_success "CPU-only restore" env \
	CRIU_CUDA_MOCK_DRIVER_VERSION_ERROR=1 \
	CRIU_CUDA_MOCK_CLI_FAIL=1 \
	CRIU_CUDA_MOCK_CLI_MARKER="$CLI_MARKER" \
	PATH="$MOCK_DIR:$PATH" \
	LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" restore \
	--no-default-config \
	--images-dir "$NO_CUDA_IMAGES" \
	--log-file restore.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--plugin-option=cuda_plugin.backend=cuda-checkpoint \
	--shell-job \
	--restore-detached

NO_CUDA_LOG="$NO_CUDA_IMAGES/restore.log"
if grep -Eq "selected (Driver API|cuda-checkpoint CLI) backend|cuDriverGetVersion" "$NO_CUDA_LOG"; then
	echo "restore without CUDA inventory probed a CUDA backend"
	exit 1
fi
if [ -e "$CLI_MARKER" ]; then
	echo "restore without CUDA inventory invoked the CLI backend"
	exit 1
fi
kill "$TARGET_PID"
wait "$TARGET_PID" 2>/dev/null || true
TARGET_PID=

# Create an image whose CUDA requirement was recorded through the direct
# backend. The inventory identity is backend-neutral, so an older driver can
# restore the same image through the CLI backend.
CUDA_IMAGES="$WORK_DIR/cuda-images"
mkdir "$CUDA_IMAGES"
sleep 300 &
TARGET_PID=$!
run_success "CUDA Driver API dump" env \
	CRIU_FAULT=138 \
	LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" dump \
	--no-default-config \
	--tree "$TARGET_PID" \
	--images-dir "$CUDA_IMAGES" \
	--log-file dump.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--shell-job \
	--timeout 10
wait "$TARGET_PID" 2>/dev/null || true

# If neither backend is usable, initialization leaves the exact inventory
# requirement unconsumed and normal inventory validation rejects the restore.
set +e
timeout 30s env \
	CRIU_FAULT=138 \
	PATH="$EMPTY_PATH" \
	LD_LIBRARY_PATH="$MOCK_DIR/unsupported${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" restore \
	--no-default-config \
	--images-dir "$CUDA_IMAGES" \
	--log-file restore-unavailable.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--shell-job \
	--restore-detached
STATUS=$?
set -e
if [ "$STATUS" -eq 0 ]; then
	echo "required CUDA restore unexpectedly succeeded without a backend"
	exit 1
fi
if [ "$STATUS" -eq 124 ]; then
	echo "required CUDA restore without a backend timed out"
	exit 1
fi
grep -q "Missing required plugin: cuda_plugin" "$CUDA_IMAGES/restore-unavailable.log"

# The same below-floor Driver API is restorable when cuda-checkpoint is
# available. Only the CLI backend from the one installed plugin is selected.
FALLBACK_CLI_MARKER="$CUDA_IMAGES/cli-invoked"
run_success "cuda-checkpoint CLI restore" env \
	CRIU_FAULT=138 \
	CRIU_CUDA_MOCK_CLI_MARKER="$FALLBACK_CLI_MARKER" \
	PATH="$MOCK_DIR:$PATH" \
	LD_LIBRARY_PATH="$MOCK_DIR/unsupported${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" restore \
	--no-default-config \
	--images-dir "$CUDA_IMAGES" \
	--log-file restore-fallback.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--shell-job \
	--restore-detached

FALLBACK_LOG="$CUDA_IMAGES/restore-fallback.log"
grep -q "selected cuda-checkpoint CLI backend" "$FALLBACK_LOG"
if grep -q "selected Driver API backend" "$FALLBACK_LOG"; then
	echo "below-floor Driver API unexpectedly handled restore"
	exit 1
fi
if [ ! -s "$FALLBACK_CLI_MARKER" ]; then
	echo "cuda-checkpoint CLI restore backend was not invoked"
	exit 1
fi

kill "$TARGET_PID"
wait "$TARGET_PID" 2>/dev/null || true
TARGET_PID=

echo "CUDA restore backend selection PASS"
