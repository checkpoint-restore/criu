#!/bin/sh
#
# Check a CRIU binary built by `make static`: it has exactly the given
# plugins built in, plugin directories are rejected, and a process
# survives a dump and restore.
#
# Usage: run.sh [CRIU [PLUGIN...]]

set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "Run this test as root." >&2
	exit 1
fi

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
CRIU=$(readlink -f -- "${1:-$ROOT/criu/criu}")
if [ "$#" -gt 0 ]; then
	shift
fi
if [ ! -x "$CRIU" ]; then
	echo "CRIU binary is not executable: $CRIU" >&2
	exit 1
fi
WORK_DIR=$(mktemp -d)
TARGET_PID=

cleanup()
{
	status=$?
	if [ -n "$TARGET_PID" ]; then
		kill -KILL "$TARGET_PID" 2>/dev/null || true
		wait "$TARGET_PID" 2>/dev/null || true
	fi
	if [ -f "$WORK_DIR/restore.pid" ]; then
		kill -KILL "$(cat "$WORK_DIR/restore.pid")" 2>/dev/null || true
	fi
	if [ "$status" -eq 0 ]; then
		rm -rf "$WORK_DIR"
	else
		echo "Keeping $WORK_DIR" >&2
	fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

run_criu()
{
	expected=$1
	shift
	set +e
	timeout 30s "$@"
	status=$?
	set -e
	if [ "$status" -eq 124 ]; then
		echo "CRIU command timed out: $*" >&2
		exit 1
	fi
	if { [ "$expected" = success ] && [ "$status" -ne 0 ]; } ||
	   { [ "$expected" = failure ] && [ "$status" -eq 0 ]; }; then
		echo "Unexpected CRIU status $status: $*" >&2
		exit 1
	fi
}

expected=none
if [ "$#" -gt 0 ]; then
	expected=$(printf '%s_plugin\n' "$@" | sort | tr '\n' ' ')
	expected=${expected% }
fi
plugins=$("$CRIU" --version | sed -n 's/^Plugins: //p')
if [ "$plugins" != "$expected" ]; then
	echo "Expected plugins '$expected', got '$plugins'" >&2
	exit 1
fi

unset CRIU_LIBS_DIR
mkdir "$WORK_DIR/plugins" "$WORK_DIR/requests" "$WORK_DIR/images"

run_criu failure "$CRIU" dump --no-default-config --tree 2147483647 \
	--images-dir "$WORK_DIR/requests" --log-file libdir.log --shell-job \
	--libdir "$WORK_DIR/plugins"
grep -q 'A static CRIU binary cannot load plugins' "$WORK_DIR/requests/libdir.log"
run_criu failure env CRIU_LIBS_DIR="$WORK_DIR/plugins" "$CRIU" dump \
	--no-default-config --tree 2147483647 --images-dir "$WORK_DIR/requests" \
	--log-file environment.log --shell-job
grep -q 'A static CRIU binary cannot load plugins' "$WORK_DIR/requests/environment.log"

# Isolate the checkpointed stdin from the test runner even though sleep does not read it.
# shellcheck disable=SC2217
sleep 300 </dev/null >"$WORK_DIR/task.log" 2>&1 &
TARGET_PID=$!
run_criu success "$CRIU" dump --no-default-config --tree "$TARGET_PID" \
	--images-dir "$WORK_DIR/images" --log-file dump.log --shell-job
wait "$TARGET_PID" 2>/dev/null || true
TARGET_PID=
run_criu success "$CRIU" restore --no-default-config \
	--images-dir "$WORK_DIR/images" --log-file restore.log --shell-job \
	--restore-detached --pidfile "$WORK_DIR/restore.pid"
test "$(cat "/proc/$(cat "$WORK_DIR/restore.pid")/comm")" = sleep

echo "Static CRIU checks PASS"
