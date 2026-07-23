#!/bin/sh

set -eu

# Verify that CRIU restores a process when the mock CUDA checkpoint operation
# changes its state and then reports an error. The target is an ordinary
# process; libcuda.so.1 is provided by the test mock, so no GPU is required.
#
# The test intentionally checks the CRIU log as well as the target process:
# the dump must fail, rollback must run, and the target must remain alive and
# no longer be traced.

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CRIU="$ROOT/criu/criu"
PLUGIN_DIR="$ROOT/plugins/cuda"
MOCK_DIR="$ROOT/test/cuda-checkpoint"
WORK_DIR=$(mktemp -d)
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

make -C "$ROOT" cuda_plugin
make -C "$MOCK_DIR"

mkdir "$WORK_DIR/images"
# The target is an ordinary process; the mock supplies synthetic CUDA state.
sleep 300 &
TARGET_PID=$!

set +e
timeout 30s env \
	CRIU_FAULT=138 \
	CRIU_CUDA_MOCK_CHECKPOINT_ERROR_AFTER_TRANSITION=1 \
	LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" dump \
	--no-default-config \
	--tree "$TARGET_PID" \
	--images-dir "$WORK_DIR/images" \
	--log-file dump.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	-R \
	--timeout 10
STATUS=$?
set -e

LOG="$WORK_DIR/images/dump.log"
if [ "$STATUS" -eq 0 ]; then
	echo "CUDA mock checkpoint unexpectedly succeeded"
	exit 1
fi
if [ "$STATUS" -eq 124 ]; then
	echo "CUDA mock rollback timed out"
	exit 1
fi
if ! kill -0 "$TARGET_PID" 2>/dev/null; then
	echo "CUDA mock checkpoint left the target dead"
	exit 1
fi
if [ "$(awk '/^TracerPid:/ { print $2 }' "/proc/$TARGET_PID/status")" != "0" ]; then
	echo "CUDA mock checkpoint left the target traced"
	exit 1
fi
if ! grep -q "cuCheckpointProcessCheckpoint($TARGET_PID) failed" "$LOG"; then
	echo "CUDA mock did not trigger the injected failure"
	exit 1
fi
if ! grep -q "resuming devices on pid $TARGET_PID" "$LOG"; then
	echo "CUDA mock did not run rollback"
	exit 1
fi
if grep -Eq "cuCheckpointProcess(Restore|Unlock).*failed|Unable to restore CUDA state" "$LOG"; then
	echo "CUDA mock rollback failed"
	exit 1
fi

echo "CUDA mock error-after-transition rollback PASS"
