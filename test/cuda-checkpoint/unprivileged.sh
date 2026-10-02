#!/bin/sh

set -eu

# Verify that `criu --unprivileged` can dump and restore a CUDA task that does
# not use seccomp, with both backends. CRIU runs as root of a new user
# namespace, so it has no CAP_SYS_ADMIN in the initial user namespace and the
# kernel refuses PTRACE_O_SUSPEND_SECCOMP (#3089). The target is an ordinary
# process; the mock supplies synthetic CUDA state, so no GPU is required.

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CRIU="$ROOT/criu/criu"
PLUGIN_DIR="$ROOT/plugins/cuda"
MOCK_DIR="$ROOT/test/cuda-checkpoint"

run_criu()
{
	timeout 30s env \
		CRIU_FAULT=138 \
		CRIU_CUDA_MOCK_STATE_FILE="$WORK_DIR/state" \
		PATH="$MOCK_DIR:$PATH" \
		LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
		"$CRIU" "$@" \
		--no-default-config \
		--images-dir "$WORK_DIR" \
		--verbosity=4 \
		--libdir "$PLUGIN_DIR" \
		--unprivileged \
		--plugin-option=cuda_plugin.backend="$BACKEND"
}

# Runs as pid 1 of a new user, pid and mount namespace.
if [ "${1:-}" = "--in-userns" ]; then
	WORK_DIR=$2
	BACKEND=$3
	setsid sleep 300 </dev/null >/dev/null 2>&1 &
	TARGET_PID=$!
	run_criu dump --tree "$TARGET_PID" --log-file dump.log
	# The dump killed the target; reap it so that restore can reuse its pid.
	wait "$TARGET_PID" 2>/dev/null || true
	echo checkpointed >"$WORK_DIR/state"
	CRIU_CUDA_MOCK_INITIAL_STATE=checkpointed run_criu restore --restore-detached --log-file restore.log
	kill -0 "$TARGET_PID"
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
		echo "CUDA mock unprivileged dump/restore failed with the $BACKEND backend"
		exit 1
	fi
	# Make sure that the plugin handled the task in both steps.
	if ! grep -q "Checkpointing CUDA devices on pid" "$WORK_DIR/$BACKEND/dump.log" ||
	   ! grep -q "resuming devices on pid" "$WORK_DIR/$BACKEND/restore.log"; then
		echo "CUDA plugin did not handle the task with the $BACKEND backend"
		exit 1
	fi
done

echo "CUDA mock unprivileged dump/restore PASS"
