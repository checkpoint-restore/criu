#!/bin/sh

set -eu

# Verify that criu dump refuses a CUDA task whose seccomp mode changes while
# the CUDA plugin lets its restore thread run, with both backends. CRIU
# decides from the seccomp mode that it collected when it seized a thread
# whether to suspend seccomp for the parasite and whether to dump the
# thread's seccomp filters. The target installs a filter during the mocked
# checkpoint action: the dump must fail, and the plugin must roll the CUDA
# state back, so that the task keeps running with its filter. CRIU runs
# with --unprivileged as root of a new user namespace, like unprivileged.sh;
# no GPU is required.

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CRIU="$ROOT/criu/criu"
PLUGIN_DIR="$ROOT/plugins/cuda"
MOCK_DIR="$ROOT/test/cuda-checkpoint"

# Runs as pid 1 of a new user, pid and mount namespace.
if [ "${1:-}" = "--in-userns" ]; then
	WORK_DIR=$2
	BACKEND=$3
	setsid "$MOCK_DIR/seccomp-mode-change" "$WORK_DIR/api" "$WORK_DIR/filtered" \
		</dev/null >/dev/null 2>&1 &
	TARGET_PID=$!
	if timeout 30s env \
		CRIU_FAULT=138 \
		CRIU_CUDA_MOCK_STATE_FILE="$WORK_DIR/state" \
		CRIU_CUDA_MOCK_API_MARKER="$WORK_DIR/api" \
		CRIU_CUDA_MOCK_CHECKPOINT_WAIT="$WORK_DIR/filtered" \
		PATH="$MOCK_DIR:$PATH" \
		LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
		"$CRIU" dump --tree "$TARGET_PID" \
		--no-default-config \
		--images-dir "$WORK_DIR" \
		--log-file dump.log \
		--verbosity=4 \
		--libdir "$PLUGIN_DIR" \
		--unprivileged \
		--plugin-option=cuda_plugin.backend="$BACKEND"; then
		echo "criu dump did not fail"
		exit 1
	fi
	LOG="$WORK_DIR/dump.log"
	if ! grep -q "Seccomp mode of thread $TARGET_PID changed from 0 to 2" "$LOG"; then
		echo "criu dump did not detect the seccomp mode change"
		exit 1
	fi
	if ! grep -q "resuming devices on pid $TARGET_PID" "$LOG" ||
	   grep -q "Unable to restore CUDA state" "$LOG"; then
		echo "CUDA plugin did not roll the CUDA state back"
		exit 1
	fi
	if ! kill -0 "$TARGET_PID" 2>/dev/null; then
		echo "criu dump left the target dead"
		exit 1
	fi
	if [ "$(awk '/^Seccomp:/ { print $2 }' "/proc/$TARGET_PID/status")" != "2" ]; then
		echo "The target lost its seccomp filter"
		exit 1
	fi
	kill "$TARGET_PID"
	exit 0
fi

WORK_DIR=$(mktemp -d)
cleanup()
{
	status=$?
	# Keep CRIU logs from a failed run for inspection.
	if [ "$status" -eq 0 ]; then
		rm -rf "$WORK_DIR"
	else
		echo "Keeping $WORK_DIR" >&2
	fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

make -C "$ROOT" cuda_plugin
make -C "$MOCK_DIR"

if ! unshare -Ur true 2>/dev/null; then
	echo "SKIP: user namespaces are not available"
	exit 0
fi

for BACKEND in driver-api cuda-checkpoint; do
	mkdir "$WORK_DIR/$BACKEND"
	if ! unshare -Urpf --mount-proc "$0" --in-userns "$WORK_DIR/$BACKEND" "$BACKEND"; then
		grep -h "Error" "$WORK_DIR/$BACKEND"/*.log >&2 || true
		echo "CUDA mock seccomp mode change test failed with the $BACKEND backend"
		exit 1
	fi
done

echo "CUDA mock seccomp mode change PASS"
