#!/bin/sh
# Custom-storage mode (cuda_plugin.custom-storage=auto|on|off) against the mock Driver API: the mock's
# device memory is filled from a file on checkpoint and written to another file after restore; both
# must match. "off" keeps the regular path and "on" fails without the API. Restore follows the image,
# whatever the restoring driver supports.

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
CRIU="$ROOT/criu/criu"
MOCK_DIR="$ROOT/test/cuda-checkpoint"
WORK_DIR=$(mktemp -d)
TARGET_PID=
FULL_DIR=

cleanup()
{
	status=$?
	if [ -n "$TARGET_PID" ]; then
		kill "$TARGET_PID" 2>/dev/null || true
		wait "$TARGET_PID" 2>/dev/null || true
	fi
	[ -z "$FULL_DIR" ] || umount "$FULL_DIR" || true
	# Keep CRIU logs from a failed run for inspection.
	if [ "$status" -eq 0 ]; then
		rm -rf "$WORK_DIR"
	else
		echo "Keeping $WORK_DIR" >&2
	fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

fail()
{
	echo "$*"
	exit 1
}

# Kill a restored target and wait until its PID is free again for the next restore.
stop_target()
{
	kill "$TARGET_PID"
	for _ in $(seq 100); do
		[ -d "/proc/$TARGET_PID" ] || return 0
		sleep 0.1
	done
	fail "restored process $TARGET_PID did not go away"
}

# criu <action> <images> <mock library dir> [criu options...]
criu()
{
	ACTION=$1
	IMAGES=$2
	LIB_DIR=$3
	shift 3
	timeout 60s env \
		CRIU_FAULT=138 \
		CRIU_CUDA_MOCK_INITIAL_STATE="$([ "$ACTION" = restore ] && echo checkpointed || echo running)" \
		CRIU_CUDA_MOCK_CS_INPUT="$WORK_DIR/gpu-in" \
		CRIU_CUDA_MOCK_CS_OUTPUT="$WORK_DIR/gpu-out" \
		CRIU_CUDA_MOCK_NVML_PID="${TARGET_PID:-}" \
		CUDA_CS_THREADS="${CS_THREADS:-4}" \
		PATH="$MOCK_DIR:$PATH" \
		LD_LIBRARY_PATH="$LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
		"$CRIU" "$ACTION" --no-default-config --images-dir "$IMAGES" --log-file "$ACTION.log" \
		--verbosity=4 --libdir "$ROOT/plugins/cuda" --shell-job "$@"
}

# dump <images> <mock library dir> <custom-storage mode>; STALE=1 plants a gpu-cs image from an earlier dump
dump()
{
	mkdir "$1"
	sleep 300 &
	TARGET_PID=$!
	[ -z "${STALE:-}" ] || cp "$CS_IMAGE" "$1/gpu-cs-$TARGET_PID.img"
	STATUS=0
	criu dump "$1" "$2" --tree "$TARGET_PID" --timeout 10 --plugin-option "cuda_plugin.custom-storage=$3" ||
		STATUS=$?
	kill "$TARGET_PID" 2>/dev/null || true
	wait "$TARGET_PID" 2>/dev/null || true
	return "$STATUS"
}

# NVML lists init pid namespace pids: from another one (a CI container), CRIU cannot find the GPUs of the
# task, so it does not use custom storage at dump.
if [ "$(stat -L -c %i /proc/self/ns/pid)" != 4026531836 ]; then
	echo "CUDA custom storage SKIP: not in the init pid namespace"
	exit 0
fi

make -C "$ROOT" cuda_plugin
make -C "$MOCK_DIR"

# Two devices (the mock's default), each with two full 64 MiB transfer chunks and a partial, unaligned
# one: three workers move them in parallel.
head -c $((4 * 64 * 1024 * 1024 + 4093)) /dev/urandom >"$WORK_DIR/gpu-in"

# auto: the API is there, so the GPU memory goes through gpu-cs-<pid>.img and comes back intact.
# Each worker's two pinned buffers serve every device: 3 workers, 6 allocations.
export CRIU_CUDA_MOCK_CS_MAX_HOST_ALLOCS=6
# CRIU only creates contexts on the 2 GPUs of the task, not on the other 2 it sees.
export CRIU_CUDA_MOCK_CTX_MARKER="$WORK_DIR/contexts"
dump "$WORK_DIR/auto" "$MOCK_DIR/custom-storage" auto || fail "auto: dump failed"
[ "$(sort -u "$CRIU_CUDA_MOCK_CTX_MARKER" | tr '\n' ' ')" = "0 1 " ] || fail "auto: unexpected contexts at dump"
rm "$CRIU_CUDA_MOCK_CTX_MARKER"
CS_IMAGE="$WORK_DIR/auto/gpu-cs-$TARGET_PID.img"
[ -s "$CS_IMAGE" ] || fail "auto: no $CS_IMAGE"
[ "$(grep -c "custom-storage checkpoint copy: .*, 3 threads," "$WORK_DIR/auto/dump.log")" -eq 2 ] ||
	fail "auto: dump did not use 3 workers on each of the 2 devices"
criu restore "$WORK_DIR/auto" "$MOCK_DIR/custom-storage" --restore-detached || fail "auto: restore failed"
cmp "$WORK_DIR/gpu-in" "$WORK_DIR/gpu-out" || fail "auto: restored GPU memory differs"
[ "$(grep -c "custom-storage restore copy: .*, 3 threads," "$WORK_DIR/auto/restore.log")" -eq 2 ] ||
	fail "auto: restore did not use 3 workers on each of the 2 devices"
[ "$(sort -u "$CRIU_CUDA_MOCK_CTX_MARKER" | tr '\n' ' ')" = "0 1 " ] || fail "auto: contexts on other GPUs at restore"
rm "$CRIU_CUDA_MOCK_CTX_MARKER"
unset CRIU_CUDA_MOCK_CS_MAX_HOST_ALLOCS CRIU_CUDA_MOCK_CTX_MARKER
stop_target

# One worker per device moves all three chunks, cycling through its two pinned buffers.
rm "$WORK_DIR/gpu-out"
CS_THREADS=1
criu restore "$WORK_DIR/auto" "$MOCK_DIR/custom-storage" --restore-detached || fail "1 worker: restore failed"
CS_THREADS=
cmp "$WORK_DIR/gpu-in" "$WORK_DIR/gpu-out" || fail "1 worker: restored GPU memory differs"
grep -q "custom-storage restore copy: .*, 1 threads," "$WORK_DIR/auto/restore.log" || fail "1 worker: not 1 thread"
stop_target

# The restored bytes come from the image: corrupt one and the output differs.
printf 'X' | dd of="$CS_IMAGE" bs=1 seek=8192 conv=notrunc status=none
criu restore "$WORK_DIR/auto" "$MOCK_DIR/custom-storage" --restore-detached || fail "corrupted: restore failed"
stop_target
TARGET_PID=
if cmp -s "$WORK_DIR/gpu-in" "$WORK_DIR/gpu-out"; then
	fail "corrupted: restored GPU memory did not come from the image"
fi

# One worker per device also dumps all three chunks, copying each one while it writes the previous one.
CS_THREADS=1
dump "$WORK_DIR/one" "$MOCK_DIR/custom-storage" auto || fail "1 worker: dump failed"
CS_THREADS=
grep -q "custom-storage checkpoint copy: .*, 1 threads," "$WORK_DIR/one/dump.log" || fail "1 worker: dump not 1 thread"
ONE_PID=$TARGET_PID
ONE_IMAGE="$WORK_DIR/one/gpu-cs-$TARGET_PID.img"
[ "$(head -c 4 "$ONE_IMAGE")" = CUCS ] || fail "image: no CUCS magic"
# The first device ends inside its last 4 KiB block, after a full chunk went through the same buffer:
# the rest of that block is zeroed, not left over from the earlier chunk.
DEV0_END=$((4096 + $(stat -c %s "$WORK_DIR/gpu-in") / 2))
PAD=$(((4096 - DEV0_END % 4096) % 4096))
[ "$PAD" -gt 0 ] || fail "image: the test needs a partial block"
[ "$(dd if="$ONE_IMAGE" bs=1 skip="$DEV0_END" count="$PAD" status=none | tr -d '\0' | wc -c)" -eq 0 ] ||
	fail "image: padding not zeroed"
rm "$WORK_DIR/gpu-out"
criu restore "$WORK_DIR/one" "$MOCK_DIR/custom-storage" --restore-detached || fail "1 worker: restore failed"
cmp "$WORK_DIR/gpu-in" "$WORK_DIR/gpu-out" || fail "1 worker: dumped GPU memory differs"
stop_target
TARGET_PID=

# An image of an unknown version is rejected. The header payload starts at byte 8 with the version
# field: 0x08 then its value.
mkdir "$WORK_DIR/version"
cp -a "$WORK_DIR/one"/. "$WORK_DIR/version/"
printf '\002' | dd of="$WORK_DIR/version/$(basename "$ONE_IMAGE")" bs=1 seek=9 conv=notrunc status=none
if criu restore "$WORK_DIR/version" "$MOCK_DIR/custom-storage" --restore-detached; then
	fail "version: restore succeeded"
fi
grep -q "unsupported version 2" "$WORK_DIR/version/restore.log" || fail "version: missing error"

# The driver may list the devices in any order, and a restore may move the task to other GPUs, as when a
# container gets another GPU: each device's memory goes to the GPU the device map gives for its own.
rm -f "$WORK_DIR/gpu-out" "$WORK_DIR/contexts"
if ! CRIU_CUDA_MOCK_CTX_MARKER="$WORK_DIR/contexts" CRIU_CUDA_MOCK_CS_REVERSE=1 CRIU_CUDA_MOCK_UUID_OFFSET=64 \
	criu restore "$WORK_DIR/one" "$MOCK_DIR/custom-storage" --restore-detached \
	--plugin-option cuda_plugin.device-map=0=1,1=0,2=2,3=3; then
	fail "remap: restore failed"
fi
[ "$(sort -u "$WORK_DIR/contexts" | tr '\n' ' ')" = "0 1 " ] || fail "remap: contexts on GPUs the map does not use"
TARGET_PID=$ONE_PID
stop_target
TARGET_PID=
cmp "$WORK_DIR/gpu-in" "$WORK_DIR/gpu-out" || fail "remap: GPU memory restored on the wrong GPUs"
# Without a device map, two GPUs that both changed cannot be told apart.
if CRIU_CUDA_MOCK_UUID_OFFSET=64 criu restore "$WORK_DIR/one" "$MOCK_DIR/custom-storage" --restore-detached; then
	fail "other GPUs: restore succeeded"
fi
grep -q "2 GPUs changed since the checkpoint.*: restoring them needs cuda_plugin.device-map" \
	"$WORK_DIR/one/restore.log" || fail "other GPUs: missing error"

# A task on one GPU restores onto another one without a device map, as a container given another GPU does.
export CRIU_CUDA_MOCK_CS_DEVICES=1
dump "$WORK_DIR/single" "$MOCK_DIR/custom-storage" auto || fail "single GPU: dump failed"
SINGLE_PID=$TARGET_PID
TARGET_PID=
# CRIU sees all the GPUs: which one replaces the task's is unknown.
if CRIU_CUDA_MOCK_UUID_OFFSET=64 criu restore "$WORK_DIR/single" "$MOCK_DIR/custom-storage" --restore-detached; then
	fail "single GPU: restore among several other GPUs succeeded"
fi
grep -q "1 GPUs changed since the checkpoint and CRIU sees 4 other GPUs" "$WORK_DIR/single/restore.log" ||
	fail "single GPU: missing error"
# CRIU sees only the GPU given to the container, as under its device cgroup.
rm -f "$WORK_DIR/gpu-out"
CRIU_CUDA_MOCK_VISIBLE_GPUS=1 CRIU_CUDA_MOCK_UUID_OFFSET=64 criu restore "$WORK_DIR/single" \
	"$MOCK_DIR/custom-storage" --restore-detached || fail "single GPU: restore on another GPU failed"
TARGET_PID=$SINGLE_PID
stop_target
TARGET_PID=
unset CRIU_CUDA_MOCK_CS_DEVICES
cmp "$WORK_DIR/gpu-in" "$WORK_DIR/gpu-out" || fail "single GPU: restored GPU memory differs"
grep -q "takes the memory checkpointed on GPU" "$WORK_DIR/single/restore.log" || fail "single GPU: not reported"

# off: the API is there but must not be used.
dump "$WORK_DIR/off" "$MOCK_DIR/custom-storage" off || fail "off: dump failed"
if ls "$WORK_DIR"/off/gpu-cs-*.img >/dev/null 2>&1; then
	fail "off: a custom-storage image was written"
fi

# An image dumped without custom storage restores the regular way on a driver that has the API.
rm -f "$WORK_DIR/gpu-out"
criu restore "$WORK_DIR/off" "$MOCK_DIR/custom-storage" --restore-detached || fail "off: restore failed"
stop_target
TARGET_PID=
! grep -q "custom-storage restore copy" "$WORK_DIR/off/restore.log" || fail "off: restore used custom storage"
[ ! -e "$WORK_DIR/gpu-out" ] || fail "off: restore went through custom storage"

# A dump without custom storage removes the gpu-cs image an earlier dump left for the same pid.
STALE=1
dump "$WORK_DIR/stale" "$MOCK_DIR/custom-storage" off || fail "stale: dump failed"
STALE=
TARGET_PID=
if ls "$WORK_DIR"/stale/gpu-cs-*.img >/dev/null 2>&1; then
	fail "stale: the earlier gpu-cs image was kept"
fi

# An image dumped with custom storage cannot be restored without it.
CS_IMAGES="$WORK_DIR/auto"
if criu restore "$CS_IMAGES" "$MOCK_DIR" --restore-detached; then
	fail "no API: restore of a custom-storage image succeeded"
fi
grep -q "checkpointed to custom storage, but libcuda has no custom-storage checkpoint API" \
	"$CS_IMAGES/restore.log" || fail "no API: missing error"
if criu restore "$CS_IMAGES" "$MOCK_DIR/custom-storage" --restore-detached \
	--plugin-option cuda_plugin.custom-storage=off; then
	fail "off: restore of a custom-storage image succeeded"
fi
grep -q "cannot be restored with cuda_plugin.custom-storage=off" "$CS_IMAGES/restore.log" ||
	fail "off: missing error"
if criu restore "$CS_IMAGES" "$MOCK_DIR/custom-storage" --restore-detached \
	--plugin-option cuda_plugin.backend=cuda-checkpoint; then
	fail "cuda-checkpoint: restore of a custom-storage image succeeded"
fi
grep -q "checkpointed to custom storage, which the cuda-checkpoint CLI backend cannot restore" \
	"$CS_IMAGES/restore.log" || fail "cuda-checkpoint: missing error"

# A full disk fails the dump after the driver mapped the GPU memory, which it cannot unmap without
# dropping it. No copy is kept in CRIU's memory, so the task is killed, not resumed without it.
FULL_DIR="$WORK_DIR/full"
mkdir "$FULL_DIR"
mount -t tmpfs -o size=32m tmpfs "$FULL_DIR"
rm -f "$WORK_DIR/gpu-out"
sleep 300 &
TARGET_PID=$!
if criu dump "$FULL_DIR" "$MOCK_DIR/custom-storage" --tree "$TARGET_PID" --timeout 10; then
	fail "full: dump succeeded"
fi
grep -q "GPU memory of pid $TARGET_PID was lost" "$FULL_DIR/dump.log" || fail "full: loss not reported"
wait "$TARGET_PID" 2>/dev/null || true
kill -0 "$TARGET_PID" 2>/dev/null && fail "full: the task without its GPU memory was resumed"
if ls "$FULL_DIR"/gpu-cs-*.img >/dev/null 2>&1; then
	fail "full: a partial gpu-cs image was kept"
fi
TARGET_PID=
umount "$FULL_DIR"
FULL_DIR=

# A truncated image fails the restore, and the task does not run with incomplete GPU memory.
mkdir "$WORK_DIR/truncated"
cp -a "$CS_IMAGES"/. "$WORK_DIR/truncated/"
truncate -s 100M "$WORK_DIR/truncated/$(basename "$CS_IMAGE")"
if criu restore "$WORK_DIR/truncated" "$MOCK_DIR/custom-storage" --restore-detached; then
	fail "truncated: restore succeeded"
fi
grep -q "GPU memory of pid .* was not restored" "$WORK_DIR/truncated/restore.log" ||
	fail "truncated: missing error"

# A failed asynchronous copy, reported when synchronising, fails the restore,
if CRIU_CUDA_MOCK_CS_SYNC_ERROR=1 criu restore "$CS_IMAGES" "$MOCK_DIR/custom-storage" --restore-detached; then
	fail "sync error: restore succeeded"
fi
grep -q "Synchronize.*: mock CUDA error" "$CS_IMAGES/restore.log" || fail "sync error: restore error not reported"
# and the dump: the task is killed, not resumed without its GPU memory.
mkdir "$WORK_DIR/sync"
sleep 300 &
TARGET_PID=$!
if CRIU_CUDA_MOCK_CS_SYNC_ERROR=1 criu dump "$WORK_DIR/sync" "$MOCK_DIR/custom-storage" --tree "$TARGET_PID" \
	--timeout 10; then
	fail "sync error: dump succeeded"
fi
grep -q "Synchronize.*: mock CUDA error" "$WORK_DIR/sync/dump.log" || fail "sync error: dump error not reported"
grep -q "GPU memory of pid $TARGET_PID was lost" "$WORK_DIR/sync/dump.log" || fail "sync error: loss not reported"
wait "$TARGET_PID" 2>/dev/null || true
kill -0 "$TARGET_PID" 2>/dev/null && fail "sync error: the task without its GPU memory was resumed"
TARGET_PID=

# CRIU never guesses the GPUs of a task: without NVML, auto checkpoints it without custom storage and on
# fails the dump. A task that NVML lists on no GPU (a process that loaded CUDA but has no GPU memory) is
# checkpointed without custom storage. In neither case does CRIU retain a context.
export CRIU_CUDA_MOCK_CTX_MARKER="$WORK_DIR/contexts"
rm -f "$CRIU_CUDA_MOCK_CTX_MARKER"
CRIU_CUDA_MOCK_NVML_INIT_ERROR=1 dump "$WORK_DIR/nonvml-auto" "$MOCK_DIR/custom-storage" auto ||
	fail "no NVML: auto dump failed"
[ ! -e "$WORK_DIR/nonvml-auto/gpu-cs-$TARGET_PID.img" ] || fail "no NVML: auto wrote a custom-storage image"
grep -q "Unable to find the GPUs of pid $TARGET_PID: checkpointing it without custom storage" \
	"$WORK_DIR/nonvml-auto/dump.log" || fail "no NVML: auto did not say so"
if CRIU_CUDA_MOCK_NVML_INIT_ERROR=1 dump "$WORK_DIR/nonvml-on" "$MOCK_DIR/custom-storage" on; then
	fail "no NVML: on dump succeeded"
fi
grep -q "Unable to find the GPUs of pid $TARGET_PID for custom storage" "$WORK_DIR/nonvml-on/dump.log" ||
	fail "no NVML: on did not say so"
CRIU_CUDA_MOCK_NVML_GPUS='' dump "$WORK_DIR/nogpu" "$MOCK_DIR/custom-storage" on || fail "no GPU: dump failed"
[ ! -e "$WORK_DIR/nogpu/gpu-cs-$TARGET_PID.img" ] || fail "no GPU: wrote a custom-storage image"
grep -q "NVML lists pid $TARGET_PID on no GPU" "$WORK_DIR/nogpu/dump.log" || fail "no GPU: did not say so"
[ ! -e "$CRIU_CUDA_MOCK_CTX_MARKER" ] || fail "a context was retained for a task with no known GPU"
TARGET_PID=
unset CRIU_CUDA_MOCK_CTX_MARKER

# on: a driver without the API must fail the dump.
if dump "$WORK_DIR/on" "$MOCK_DIR" on; then
	fail "on: dump succeeded without the custom-storage API"
fi
TARGET_PID=
grep -q "custom-storage=on but libcuda has no custom-storage checkpoint API" "$WORK_DIR/on/dump.log" ||
	fail "on: missing error"

echo "CUDA custom storage PASS"
