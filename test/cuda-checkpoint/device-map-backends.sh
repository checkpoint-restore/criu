#!/bin/sh

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CRIU="$ROOT/criu/criu"
PLUGIN_BUILD_DIR="$ROOT/plugins/cuda"
MOCK_DIR="$ROOT/test/cuda-checkpoint"
WORK_DIR=$(mktemp -d)
PLUGIN_DIR="$WORK_DIR/plugins"
IMAGE_DIR="$WORK_DIR/images"
SOURCE_PID=
LIVE_PID=

cleanup()
{
	if [ -n "$LIVE_PID" ]; then
		kill "$LIVE_PID" 2>/dev/null || true
		wait "$LIVE_PID" 2>/dev/null || true
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

stop_restored_process()
{
	STOP_ATTEMPTS=0

	if [ -z "$LIVE_PID" ]; then
		return
	fi

	kill "$LIVE_PID" 2>/dev/null || true
	while kill -0 "$LIVE_PID" 2>/dev/null; do
		STOP_ATTEMPTS=$((STOP_ATTEMPTS + 1))
		if [ "$STOP_ATTEMPTS" -eq 20 ]; then
			kill -KILL "$LIVE_PID" 2>/dev/null || true
		elif [ "$STOP_ATTEMPTS" -eq 100 ]; then
			echo "restored CUDA test process $LIVE_PID did not exit"
			exit 1
		fi
		sleep 0.05
	done
	wait "$LIVE_PID" 2>/dev/null || true
	LIVE_PID=
}

check_mapping()
{
	MARKER=$1
	DESCRIPTION=$2

	if [ ! -s "$MARKER" ]; then
		echo "$DESCRIPTION did not pass a CUDA device map"
		exit 1
	fi
	if [ "$(wc -l < "$MARKER")" -ne 1 ]; then
		echo "$DESCRIPTION passed the CUDA device map more than once"
		exit 1
	fi
	if [ "$(sed -n '1p' "$MARKER")" != "$EXPECTED_MAP" ]; then
		echo "$DESCRIPTION passed an unexpected CUDA device map"
		exit 1
	fi
}

make -C "$ROOT" cuda_plugin
make -C "$MOCK_DIR"

mkdir "$PLUGIN_DIR" "$IMAGE_DIR"
cp "$PLUGIN_BUILD_DIR/cuda_plugin.so" "$PLUGIN_DIR/cuda_plugin.so"

# Device mapping is restore-only and must fail before either checkpoint
# backend is probed during dump.
INVALID_IMAGE_DIR="$WORK_DIR/invalid-dump-images"
mkdir "$INVALID_IMAGE_DIR"
sleep 300 &
SOURCE_PID=$!
LIVE_PID=$SOURCE_PID
CLI_PROBE_MARKER="$INVALID_IMAGE_DIR/cli-invoked"
DRIVER_PROBE_MARKER="$INVALID_IMAGE_DIR/driver-probed"
set +e
timeout 30s env \
	CRIU_FAULT=138 \
	CRIU_CUDA_MOCK_CLI_MARKER="$CLI_PROBE_MARKER" \
	CRIU_CUDA_MOCK_DRIVER_MARKER="$DRIVER_PROBE_MARKER" \
	PATH="$MOCK_DIR:$PATH" \
	LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" dump \
	--no-default-config \
	--tree "$SOURCE_PID" \
	--images-dir "$INVALID_IMAGE_DIR" \
	--log-file dump.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--plugin-option=cuda_plugin.device-map=auto \
	--shell-job \
	-R \
	--timeout 10
STATUS=$?
set -e
if [ "$STATUS" -eq 0 ]; then
	echo "dump with cuda_plugin.device-map unexpectedly succeeded"
	exit 1
fi
if [ "$STATUS" -eq 124 ]; then
	echo "dump with cuda_plugin.device-map timed out"
	exit 1
fi
grep -q "cuda_plugin.device-map is valid only during restore" \
	"$INVALID_IMAGE_DIR/dump.log"
if [ -e "$CLI_PROBE_MARKER" ] || [ -e "$DRIVER_PROBE_MARKER" ]; then
	echo "dump with cuda_plugin.device-map probed a backend"
	exit 1
fi
stop_restored_process

# Record source UUIDs 00..3f in the image. Restore enumerates destination UUIDs
# 40..7f, so an identity string cannot accidentally satisfy these checks.
sleep 300 &
SOURCE_PID=$!
LIVE_PID=$SOURCE_PID
run_success "CUDA inventory dump" env \
	CRIU_FAULT=138 \
	CRIU_CUDA_MOCK_INITIAL_STATE=running \
	CRIU_CUDA_MOCK_UUID_OFFSET=0 \
	LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" dump \
	--no-default-config \
	--tree "$SOURCE_PID" \
	--images-dir "$IMAGE_DIR" \
	--log-file dump.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--plugin-option=cuda_plugin.backend=driver-api \
	--shell-job \
	--timeout 10
wait "$SOURCE_PID" 2>/dev/null || true
LIVE_PID=

if [ ! -s "$IMAGE_DIR/cuda-gpu-inventory.img" ]; then
	echo "CUDA dump did not create a GPU inventory image"
	exit 1
fi

SOURCE_0=GPU-00010203-0405-0607-0809-0a0b0c0d0e0f
SOURCE_1=GPU-10111213-1415-1617-1819-1a1b1c1d1e1f
SOURCE_2=GPU-20212223-2425-2627-2829-2a2b2c2d2e2f
SOURCE_3=GPU-30313233-3435-3637-3839-3a3b3c3d3e3f
DESTINATION_0=GPU-40414243-4445-4647-4849-4a4b4c4d4e4f
DESTINATION_1=GPU-50515253-5455-5657-5859-5a5b5c5d5e5f
DESTINATION_2=GPU-60616263-6465-6667-6869-6a6b6c6d6e6f
DESTINATION_3=GPU-70717273-7475-7677-7879-7a7b7c7d7e7f
EXPECTED_MAP="$SOURCE_0=$DESTINATION_0,$SOURCE_1=$DESTINATION_1,$SOURCE_2=$DESTINATION_2,$SOURCE_3=$DESTINATION_3"

# The Driver API receives the resolved CUcheckpointGpuPair array.
DRIVER_MARKER="$WORK_DIR/driver-device-map"
run_success "forced Driver API restore with automatic mapping" env \
	CRIU_FAULT=138 \
	CRIU_CUDA_MOCK_INITIAL_STATE=checkpointed \
	CRIU_CUDA_MOCK_UUID_OFFSET=64 \
	CRIU_CUDA_MOCK_DEVICE_MAP_MARKER="$DRIVER_MARKER" \
	LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" restore \
	--no-default-config \
	--images-dir "$IMAGE_DIR" \
	--log-file restore-driver.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--plugin-option=cuda_plugin.backend=driver-api \
	--plugin-option=cuda_plugin.device-map=auto \
	--shell-job \
	--restore-detached
LIVE_PID=$SOURCE_PID
check_mapping "$DRIVER_MARKER" "Driver API backend"
stop_restored_process

# The cuda-checkpoint backend receives the same resolved UUID pairs through
# its --device-map option.
CLI_MARKER="$WORK_DIR/cli-device-map"
CLI_STATE="$WORK_DIR/cli-state"
printf '%s\n' checkpointed > "$CLI_STATE"
run_success "forced cuda-checkpoint restore with automatic mapping" env \
	-u CRIU_CUDA_MOCK_NO_DEVICE_MAP \
	CRIU_FAULT=138 \
	CRIU_CUDA_MOCK_UUID_OFFSET=64 \
	CRIU_CUDA_MOCK_STATE_FILE="$CLI_STATE" \
	CRIU_CUDA_MOCK_DEVICE_MAP_MARKER="$CLI_MARKER" \
	PATH="$MOCK_DIR:$PATH" \
	LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" restore \
	--no-default-config \
	--images-dir "$IMAGE_DIR" \
	--log-file restore-cli.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--plugin-option=cuda_plugin.backend=cuda-checkpoint \
	--plugin-option=cuda_plugin.device-map=auto \
	--shell-job \
	--restore-detached
LIVE_PID=$SOURCE_PID
check_mapping "$CLI_MARKER" "cuda-checkpoint backend"
if ! cmp -s "$DRIVER_MARKER" "$CLI_MARKER"; then
	echo "CUDA backends received different canonical device maps"
	exit 1
fi
stop_restored_process

# A forced CLI backend must reject mapping before restore when the installed
# cuda-checkpoint utility does not advertise --device-map support.
UNSUPPORTED_STATE="$WORK_DIR/unsupported-cli-state"
UNSUPPORTED_MARKER="$WORK_DIR/unsupported-cli-device-map"
printf '%s\n' checkpointed > "$UNSUPPORTED_STATE"
set +e
timeout 30s env \
	CRIU_FAULT=138 \
	CRIU_CUDA_MOCK_NO_DEVICE_MAP=1 \
	CRIU_CUDA_MOCK_UUID_OFFSET=64 \
	CRIU_CUDA_MOCK_STATE_FILE="$UNSUPPORTED_STATE" \
	CRIU_CUDA_MOCK_DEVICE_MAP_MARKER="$UNSUPPORTED_MARKER" \
	PATH="$MOCK_DIR:$PATH" \
	LD_LIBRARY_PATH="$MOCK_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$CRIU" restore \
	--no-default-config \
	--images-dir "$IMAGE_DIR" \
	--log-file restore-cli-unsupported.log \
	--verbosity=4 \
	--libdir "$PLUGIN_DIR" \
	--plugin-option=cuda_plugin.backend=cuda-checkpoint \
	--plugin-option=cuda_plugin.device-map=auto \
	--shell-job \
	--restore-detached
STATUS=$?
set -e
if [ "$STATUS" -eq 0 ]; then
	LIVE_PID=$SOURCE_PID
	echo "cuda-checkpoint without device-map support unexpectedly restored the image"
	exit 1
fi
if [ "$STATUS" -eq 124 ]; then
	echo "cuda-checkpoint device-map capability failure timed out"
	exit 1
fi
grep -q "cuda-checkpoint with --device-map support is unavailable" \
	"$IMAGE_DIR/restore-cli-unsupported.log"
grep -q "Requested cuda-checkpoint CLI backend is unavailable: -95" \
	"$IMAGE_DIR/restore-cli-unsupported.log"
if [ -e "$UNSUPPORTED_MARKER" ]; then
	echo "unsupported cuda-checkpoint backend received a device map"
	exit 1
fi

echo "CUDA device-map backend integration PASS"
