#!/bin/sh

set -eu

# Exercise backend selection inside the single CUDA plugin. Selection is
# allowed only during initialization: runtime or probe errors must not be
# hidden by switching to the other backend.

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CRIU="$ROOT/criu/criu"
PLUGIN_BUILD_DIR="$ROOT/plugins/cuda"
MOCK_DIR="$ROOT/test/cuda-checkpoint"
WORK_DIR=$(mktemp -d)
PLUGIN_DIR="$WORK_DIR/plugins"
TARGET_PID=
CASE_NUMBER=0

cleanup()
{
	if [ -n "$TARGET_PID" ]; then
		kill "$TARGET_PID" 2>/dev/null || true
		wait "$TARGET_PID" 2>/dev/null || true
	fi
	rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

next_case()
{
	CASE_NUMBER=$((CASE_NUMBER + 1))
	IMAGE_DIR="$WORK_DIR/images-$CASE_NUMBER"
	mkdir "$IMAGE_DIR"
	sleep 300 &
	TARGET_PID=$!
}

stop_target()
{
	kill "$TARGET_PID" 2>/dev/null || true
	wait "$TARGET_PID" 2>/dev/null || true
	TARGET_PID=
}

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

mkdir "$PLUGIN_DIR"
cp "$PLUGIN_BUILD_DIR/cuda_plugin.so" "$PLUGIN_DIR/cuda_plugin.so"

# A supported Driver API wins even when the CLI is installed. Make every CLI
# invocation fail so success also proves that the fallback was not probed.
next_case
CLI_MARKER="$IMAGE_DIR/cli-invoked"
run_success "supported Driver API dump" env \
	CRIU_FAULT=138 \
	CRIU_CUDA_MOCK_CLI_FAIL=1 \
	CRIU_CUDA_MOCK_CLI_MARKER="$CLI_MARKER" \
	PATH="$MOCK_DIR:$PATH" \
	LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" dump \
	--no-default-config \
	--tree "$TARGET_PID" \
	--images-dir "$IMAGE_DIR" \
	--log-file dump.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--shell-job \
	-R \
	--timeout 10
grep -q "selected Driver API backend" "$IMAGE_DIR/dump.log"
if grep -q "selected cuda-checkpoint CLI backend" "$IMAGE_DIR/dump.log"; then
	echo "supported Driver API unexpectedly selected the CLI backend"
	exit 1
fi
if [ -e "$CLI_MARKER" ]; then
	echo "supported Driver API unexpectedly probed the CLI backend"
	exit 1
fi
stop_target

# Drivers below the direct API support floor use the CLI backend from the same
# shared object. An explicit auto value has the same behavior as omission.
next_case
CLI_MARKER="$IMAGE_DIR/cli-invoked"
run_success "cuda-checkpoint CLI fallback dump" env \
	CRIU_FAULT=138 \
	CRIU_CUDA_MOCK_CLI_MARKER="$CLI_MARKER" \
	PATH="$MOCK_DIR:$PATH" \
	LD_LIBRARY_PATH="$MOCK_DIR/unsupported${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" dump \
	--no-default-config \
	--tree "$TARGET_PID" \
	--images-dir "$IMAGE_DIR" \
	--log-file dump.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--plugin-option=cuda_plugin.backend=auto \
	--shell-job \
	-R \
	--timeout 10
grep -q "selected cuda-checkpoint CLI backend" "$IMAGE_DIR/dump.log"
if grep -q "selected Driver API backend" "$IMAGE_DIR/dump.log"; then
	echo "unsupported Driver API unexpectedly remained selected"
	exit 1
fi
if [ ! -s "$CLI_MARKER" ]; then
	echo "cuda-checkpoint CLI fallback was not invoked"
	exit 1
fi
stop_target

# Plugins receive the same argument list and ignore options they do not own.
# Repeating a recognized option preserves order, so the last value selects the
# CLI without inspecting the otherwise supported Driver API.
next_case
CLI_MARKER="$IMAGE_DIR/cli-invoked"
DRIVER_MARKER="$IMAGE_DIR/driver-probed"
run_success "forced cuda-checkpoint CLI dump" env \
	CRIU_FAULT=138 \
	CRIU_CUDA_MOCK_CLI_MARKER="$CLI_MARKER" \
	CRIU_CUDA_MOCK_DRIVER_MARKER="$DRIVER_MARKER" \
	PATH="$MOCK_DIR:$PATH" \
	LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" dump \
	--no-default-config \
	--tree "$TARGET_PID" \
	--images-dir "$IMAGE_DIR" \
	--log-file dump.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--plugin-option=cuda_plugin.backend=driver-api \
	--plugin-option=unrelated_plugin.option=value \
	--plugin-option=cuda_plugin.unknown=value \
	--plugin-option=cuda_plugin.backend=cuda-checkpoint \
	--plugin-option=cuda_plugin.back=driver-api \
	--shell-job \
	-R \
	--timeout 10
grep -q "selected cuda-checkpoint CLI backend" "$IMAGE_DIR/dump.log"
if [ -e "$DRIVER_MARKER" ]; then
	echo "forced cuda-checkpoint backend unexpectedly probed the Driver API"
	exit 1
fi
if [ ! -s "$CLI_MARKER" ]; then
	echo "forced cuda-checkpoint backend was not invoked"
	exit 1
fi
stop_target

# A forced Driver API backend below the support floor is a hard error. The
# plugin must not recover by probing the available CLI backend.
next_case
CLI_MARKER="$IMAGE_DIR/cli-invoked"
set +e
timeout 30s env \
	CRIU_FAULT=138 \
	CRIU_CUDA_MOCK_CLI_MARKER="$CLI_MARKER" \
	PATH="$MOCK_DIR:$PATH" \
	LD_LIBRARY_PATH="$MOCK_DIR/unsupported${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" dump \
	--no-default-config \
	--tree "$TARGET_PID" \
	--images-dir "$IMAGE_DIR" \
	--log-file dump.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--plugin-option=cuda_plugin.backend=driver-api \
	--shell-job \
	-R \
	--timeout 10
STATUS=$?
set -e
if [ "$STATUS" -eq 0 ]; then
	echo "forced unsupported Driver API backend unexpectedly succeeded"
	exit 1
fi
if [ "$STATUS" -eq 124 ]; then
	echo "forced unsupported Driver API backend timed out"
	exit 1
fi
grep -q "Requested Driver API backend is unavailable: -95" "$IMAGE_DIR/dump.log"
if [ -e "$CLI_MARKER" ]; then
	echo "forced unsupported Driver API backend probed the CLI backend"
	exit 1
fi
stop_target

# A forced CLI backend that cannot be probed is also a hard error and must not
# inspect an otherwise supported Driver API backend.
next_case
CLI_MARKER="$IMAGE_DIR/cli-invoked"
DRIVER_MARKER="$IMAGE_DIR/driver-probed"
set +e
timeout 30s env \
	CRIU_FAULT=138 \
	CRIU_CUDA_MOCK_CLI_FAIL=1 \
	CRIU_CUDA_MOCK_CLI_MARKER="$CLI_MARKER" \
	CRIU_CUDA_MOCK_DRIVER_MARKER="$DRIVER_MARKER" \
	PATH="$MOCK_DIR:$PATH" \
	LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" dump \
	--no-default-config \
	--tree "$TARGET_PID" \
	--images-dir "$IMAGE_DIR" \
	--log-file dump.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--plugin-option=cuda_plugin.backend=cuda-checkpoint \
	--shell-job \
	-R \
	--timeout 10
STATUS=$?
set -e
if [ "$STATUS" -eq 0 ]; then
	echo "forced unavailable cuda-checkpoint backend unexpectedly succeeded"
	exit 1
fi
if [ "$STATUS" -eq 124 ]; then
	echo "forced unavailable cuda-checkpoint backend timed out"
	exit 1
fi
grep -q "Requested cuda-checkpoint CLI backend is unavailable" "$IMAGE_DIR/dump.log"
if [ -e "$DRIVER_MARKER" ]; then
	echo "forced unavailable cuda-checkpoint backend probed the Driver API"
	exit 1
fi
stop_target

# Invalid, empty, and missing values fail before either backend is probed.
for BACKEND_ARG in backend=invalid backend= backend; do
	next_case
	CLI_MARKER="$IMAGE_DIR/cli-invoked"
	DRIVER_MARKER="$IMAGE_DIR/driver-probed"
	set +e
	timeout 30s env \
		CRIU_FAULT=138 \
		CRIU_CUDA_MOCK_CLI_MARKER="$CLI_MARKER" \
		CRIU_CUDA_MOCK_DRIVER_MARKER="$DRIVER_MARKER" \
		PATH="$MOCK_DIR:$PATH" \
		LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
		"$CRIU" dump \
		--no-default-config \
		--tree "$TARGET_PID" \
		--images-dir "$IMAGE_DIR" \
		--log-file dump.log \
		--verbosity=4 \
		--libdir "$PLUGIN_DIR" \
		"--plugin-option=cuda_plugin.$BACKEND_ARG" \
		--shell-job \
		-R \
		--timeout 10
	STATUS=$?
	set -e
	if [ "$STATUS" -eq 0 ]; then
		echo "invalid cuda_plugin.backend value unexpectedly succeeded"
		exit 1
	fi
	if [ "$STATUS" -eq 124 ]; then
		echo "invalid cuda_plugin.backend value timed out"
		exit 1
	fi
	grep -Eq "Invalid cuda_plugin.backend value|cuda_plugin.backend requires a value" "$IMAGE_DIR/dump.log"
	if [ -e "$CLI_MARKER" ] || [ -e "$DRIVER_MARKER" ]; then
		echo "invalid cuda_plugin.backend value probed a backend"
		exit 1
	fi
	stop_target
done

# A failure while querying a present Driver API is a hard initialization error,
# not evidence that the API is unsupported. It must not fall back to the CLI.
next_case
CLI_MARKER="$IMAGE_DIR/cli-invoked"
set +e
timeout 30s env \
	CRIU_FAULT=138 \
	CRIU_CUDA_MOCK_DRIVER_VERSION_ERROR=1 \
	CRIU_CUDA_MOCK_CLI_MARKER="$CLI_MARKER" \
	PATH="$MOCK_DIR:$PATH" \
	LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" dump \
	--no-default-config \
	--tree "$TARGET_PID" \
	--images-dir "$IMAGE_DIR" \
	--log-file dump.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--shell-job \
	-R \
	--timeout 10
STATUS=$?
set -e
if [ "$STATUS" -eq 0 ]; then
	echo "CUDA driver-version query error unexpectedly succeeded"
	exit 1
fi
if [ "$STATUS" -eq 124 ]; then
	echo "CUDA driver-version query error timed out"
	exit 1
fi
if ! grep -q "cuDriverGetVersion(0) failed: CUDA_ERROR_MOCK (1): mock CUDA error" "$IMAGE_DIR/dump.log"; then
	echo "CUDA driver-version query did not report the injected error"
	exit 1
fi
if ! grep -q "Unable to probe Driver API backend: -1" "$IMAGE_DIR/dump.log"; then
	echo "CUDA Driver API probe error was not propagated"
	exit 1
fi
if grep -q "selected cuda-checkpoint CLI backend" "$IMAGE_DIR/dump.log"; then
	echo "CUDA driver-version query error fell back to the CLI backend"
	exit 1
fi
if [ -e "$CLI_MARKER" ]; then
	echo "CUDA driver-version query error probed the CLI backend"
	exit 1
fi

echo "Single CUDA plugin backend selection PASS"
