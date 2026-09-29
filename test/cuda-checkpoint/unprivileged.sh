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
		CRIU_CUDA_MOCK_API_MARKER="$WORK_DIR/api" \
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

# Checks that the CUDA calls that changed the state of the target, as the
# mocks recorded them in the API marker, are $1, in this order. $2 says
# when, for the error message.
check_cuda_calls()
{
	CALLS=$(awk -v pid="$TARGET_PID" '
		$2 == pid && /^(lock|checkpoint|restore|unlock) / {
			printf "%s%s", sep, $1
			sep = " "
		}' "$WORK_DIR/api")
	if [ "$CALLS" != "$1" ]; then
		echo "The mocks recorded '$CALLS' for the target $2 instead of '$1'"
		exit 1
	fi
}

# Runs as pid 1 of a new user, pid and mount namespace.
if [ "${1:-}" = "--in-userns" ]; then
	WORK_DIR=$2
	BACKEND=$3
	setsid sleep 300 </dev/null >/dev/null 2>&1 &
	TARGET_PID=$!
	# CRIU refuses to dump a task whose session leader is outside its pid
	# namespace. Wait until setsid has made the target the leader of a new
	# session and has executed sleep. In /proc/<pid>/stat, the session is
	# the fourth field after the command name, which is in parentheses and
	# can contain spaces.
	ATTEMPTS=0
	while :; do
		if ! STAT=$(cat "/proc/$TARGET_PID/stat"); then
			echo "The target exited before it ran sleep"
			exit 1
		fi
		COMM=${STAT#* (}
		COMM=${COMM%) *}
		SESSION=$(echo "${STAT##*) }" | cut -d ' ' -f 4)
		if [ "$COMM" = sleep ] && [ "$SESSION" = "$TARGET_PID" ]; then
			break
		fi
		ATTEMPTS=$((ATTEMPTS + 1))
		if [ "$ATTEMPTS" -eq 300 ]; then
			echo "The target did not start sleep in a new session: $STAT"
			exit 1
		fi
		sleep 0.1
	done
	run_criu dump --tree "$TARGET_PID" --log-file dump.log
	# The dump killed the target; reap it so that restore can reuse its pid.
	wait "$TARGET_PID" 2>/dev/null || true
	# The plugin must have locked and checkpointed the target at dump, and
	# must restore and unlock it at restore.
	check_cuda_calls "lock checkpoint" "after the dump"
	echo checkpointed >"$WORK_DIR/state"
	CRIU_CUDA_MOCK_INITIAL_STATE=checkpointed run_criu restore --restore-detached --log-file restore.log
	check_cuda_calls "lock checkpoint restore unlock" "after the restore"
	# The cuda-checkpoint mock also records the state in a file.
	if [ "$BACKEND" = cuda-checkpoint ] && [ "$(cat "$WORK_DIR/state")" != running ]; then
		echo "The cuda-checkpoint mock does not record the restored task as running"
		exit 1
	fi
	kill -0 "$TARGET_PID"
	# Every thread of the restored task must be running, sleeping or
	# waiting for I/O, not stopped or traced.
	for STATUS_FILE in "/proc/$TARGET_PID/task/"*/status; do
		THREAD=$(awk '/^(Name|State|TracerPid):/ { printf "%s %s ", $1, $2 }' "$STATUS_FILE")
		case $THREAD in
		"Name: sleep State: "[RSD]" TracerPid: 0 ") ;;
		*)
			echo "The restored task does not run: $THREAD"
			exit 1
			;;
		esac
	done
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
