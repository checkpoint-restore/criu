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
	# Wait until setsid has made the target the leader of a new session and
	# has executed seccomp-mode-change, so that CRIU seizes the test program
	# and not the shell or setsid that start it. Check both: setsid leads
	# the new session before it executes the program, and until the shell
	# executes setsid, the target has the command name of this script, which
	# is cut to the same 15 characters as the program's. In
	# /proc/<pid>/stat, the session is the fourth field after the command
	# name, which is in parentheses and can contain spaces.
	ATTEMPTS=0
	while :; do
		if ! STAT=$(cat "/proc/$TARGET_PID/stat"); then
			echo "The target exited before it ran seccomp-mode-change"
			exit 1
		fi
		COMM=${STAT#* (}
		COMM=${COMM%) *}
		SESSION=$(echo "${STAT##*) }" | cut -d ' ' -f 4)
		if [ "$COMM" = seccomp-mode-ch ] && [ "$SESSION" = "$TARGET_PID" ]; then
			break
		fi
		ATTEMPTS=$((ATTEMPTS + 1))
		if [ "$ATTEMPTS" -eq 300 ]; then
			echo "The target did not start seccomp-mode-change in a new session: $STAT"
			exit 1
		fi
		sleep 0.1
	done
	STATUS=0
	timeout 30s env \
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
		--plugin-option=cuda_plugin.backend="$BACKEND" || STATUS=$?
	# criu exits with 1 when it refuses to dump a task. timeout exits with
	# 124 when criu does not finish in time, and with 128 + N when signal N
	# kills criu.
	if [ "$STATUS" -eq 0 ]; then
		echo "criu dump did not fail"
		exit 1
	elif [ "$STATUS" -eq 124 ]; then
		echo "criu dump timed out"
		exit 1
	elif [ "$STATUS" -gt 128 ]; then
		echo "criu dump was killed by signal $((STATUS - 128))"
		exit 1
	elif [ "$STATUS" -ne 1 ]; then
		echo "criu dump failed with status $STATUS instead of 1"
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
	# The mocks record each CUDA call in the API marker: the plugin must
	# have undone its changes to the CUDA state of the target, in reverse
	# order, and must not have changed it after that. The cuda-checkpoint
	# mock also records the state in a file. The Driver API mock keeps it
	# in CRIU's memory, and the plugin reads it again after the unlock: it
	# reports an error (checked above) unless the target runs again.
	EXPECTED="lock checkpoint restore unlock"
	CALLS=$(awk -v pid="$TARGET_PID" '
		$2 == pid && /^(lock|checkpoint|restore|unlock) / {
			printf "%s%s", sep, $1
			sep = " "
		}' "$WORK_DIR/api")
	if [ "$CALLS" != "$EXPECTED" ]; then
		echo "The mocks recorded '$CALLS' for the target instead of '$EXPECTED'"
		exit 1
	fi
	if [ "$BACKEND" = cuda-checkpoint ] && [ "$(cat "$WORK_DIR/state")" != running ]; then
		echo "The cuda-checkpoint mock does not record the target as running"
		exit 1
	fi
	if ! kill -0 "$TARGET_PID" 2>/dev/null; then
		echo "criu dump left the target dead"
		exit 1
	fi
	# Every thread of the target must still have its filter, and must be
	# running, sleeping or waiting for I/O, not stopped, traced or dead.
	for STATUS_FILE in "/proc/$TARGET_PID/task/"*/status; do
		THREAD=$(awk '/^(State|TracerPid|Seccomp):/ { printf "%s %s ", $1, $2 }' "$STATUS_FILE")
		case $THREAD in
		"State: "[RSD]" TracerPid: 0 Seccomp: 2 ") ;;
		*)
			echo "A thread of the target does not run with its filter: $THREAD"
			exit 1
			;;
		esac
	done
	# The target creates the file again when it is missing, but only while
	# uname() fails with EPERM: it must still run, with its filter.
	rm "$WORK_DIR/filtered"
	ATTEMPTS=0
	while [ ! -e "$WORK_DIR/filtered" ]; do
		if ! kill -0 "$TARGET_PID" 2>/dev/null; then
			echo "The target exited after the dump"
			exit 1
		fi
		ATTEMPTS=$((ATTEMPTS + 1))
		if [ "$ATTEMPTS" -eq 300 ]; then
			echo "The target did not run after the dump"
			exit 1
		fi
		sleep 0.1
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
		echo "CUDA mock seccomp mode change test failed with the $BACKEND backend"
		exit 1
	fi
done

echo "CUDA mock seccomp mode change PASS"
