#!/bin/sh

set -eu

# Verify that a plugin cannot consume a longer inventory name merely because
# the stored name starts with its own logical name.

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CRIU="$ROOT/criu/criu"
PLUGIN_BUILD_DIR="$ROOT/test/plugins"
WORK_DIR=$(mktemp -d)
PLUGIN_DIR="$WORK_DIR/plugins"
IMAGE_DIR="$WORK_DIR/images"
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

make -C "$ROOT" criu/criu
make -C "$PLUGIN_BUILD_DIR" inventory_exact_plugin.so

mkdir "$PLUGIN_DIR" "$IMAGE_DIR"
cp "$PLUGIN_BUILD_DIR/inventory_exact_plugin.so" "$PLUGIN_DIR/inventory-name-is-opaque.so"

sleep 300 &
TARGET_PID=$!
run_success "exact-inventory dump" "$CRIU" dump \
	--no-default-config \
	--tree "$TARGET_PID" \
	--images-dir "$IMAGE_DIR" \
	--log-file dump.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--shell-job
wait "$TARGET_PID" 2>/dev/null || true

set +e
timeout 30s "$CRIU" restore \
	--no-default-config \
	--images-dir "$IMAGE_DIR" \
	--log-file restore.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--shell-job \
	--restore-detached
STATUS=$?
set -e

if [ "$STATUS" -eq 0 ]; then
	echo "prefix inventory name was unexpectedly consumed"
	exit 1
fi
if [ "$STATUS" -eq 124 ]; then
	echo "exact-inventory restore timed out"
	exit 1
fi
grep -q "Missing required plugin: inventory_exact_extra" "$IMAGE_DIR/restore.log"
TARGET_PID=

echo "Exact plugin inventory matching PASS"
