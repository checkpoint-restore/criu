#!/usr/bin/env bash
set -euo pipefail

START_TOTAL=$(date +%s)

# Configuration
DEST_IP="172.31.15.117"
PORT=9002
IMAGES_DIR="/fsx/lazy"
LOG_FILE="$IMAGES_DIR/lazy-primary.log"
READY_FILE="$IMAGES_DIR/ready.log"
WAIT_TIMEOUT=3000  # 50 minutes

echo "CRIU Dump Configuration"
echo "  Destination IP : $DEST_IP"
echo "  Port           : $PORT"
echo "  Images Dir     : $IMAGES_DIR"
echo "  Log File       : $LOG_FILE"
echo "  Ready Signal   : $READY_FILE"
echo "----------------------------------------------------------------"


echo "Step 1: Cleaning up $IMAGES_DIR/*"
sudo rm -rf "$IMAGES_DIR"/*
echo "Cleanup complete"

# Wait for destination to be ready
echo "Waiting for destination ready signal at $READY_FILE"
START_TIME=$(date +%s)
while [ ! -f "$READY_FILE" ]; do
  ELAPSED=$(($(date +%s) - START_TIME))
  if [ $ELAPSED -ge $WAIT_TIMEOUT ]; then
    echo "Timeout: Destination ready signal not found within ${WAIT_TIMEOUT}s"
    exit 1
  fi
  sleep 0.5
done
echo "Destination is ready!"

# Get valkey-server PID
PID=$(pgrep -x valkey-server)
if [ -z "$PID" ]; then
  echo "Error: valkey-server process not found"
  exit 1
fi

echo "Found valkey-server PID: $PID"

# Close userfaultfd file descriptors if present - blocks CRIU dump
echo "Closing userfaultfd fds..."
sudo gdb -p $PID -batch -ex "call close(12)" -ex "call close(13)" -ex detach -ex quit 2>/dev/null || true

echo "Starting CRIU dump with lazy-pages..."
sudo taskset -pc 0 $(pidof valkey-server)
# Execute CRIU dump command (background - cow-dump stays running)
sudo ASAN_OPTIONS=abort_on_error=1:disable_coredump=0:detect_leaks=0 \
     UBSAN_OPTIONS=halt_on_error=1 criu dump \
  --tree "$PID" \
  --images-dir "$IMAGES_DIR" \
  --cow-dump \
  --lazy-pages \
  --address "$DEST_IP" \
  --port "$PORT" \
  --tcp-close \
  --ext-unix-sk \
  -v2 -o "$LOG_FILE" \
  --leave-running &

# Wait for dump to complete (PAGE SERVER READY signal)
echo "Waiting for dump to complete..."
for i in $(seq 1 60); do
  if grep -q "PAGE SERVER READY TO SERVE" "$LOG_FILE" 2>/dev/null; then
    echo "Dump ready"
    break
  fi
  sleep 0.5
done


END_TOTAL=$(date +%s)
DURATION=$((END_TOTAL - START_TOTAL))

MEM=$(valkey-cli info memory | grep used_memory_human | cut -d: -f2 | tr -d '\r')
KEYS=$(valkey-cli dbsize 2>/dev/null | grep -oE '[0-9]+' || echo "?")

# Extract CRIU timing from logs
DUMP_TOTAL=$(grep "dump_one_task TOTAL" "$LOG_FILE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' || echo "?")
PARSE_SMAPS=$(grep "parse_smaps took" "$LOG_FILE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' || echo "?")
DUMP_PAGES=$(grep "parasite_dump_pages_seized took" "$LOG_FILE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' || echo "?")
GEN_IOVS=$(grep "generate_vma_iovs loop" "$LOG_FILE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' || echo "?")

echo "================================================================"
echo "CRIU dump completed successfully"
echo "  Wall Clock:  ${DURATION}s"
echo "  Memory:      $MEM"
echo "  Keys:        $KEYS"
echo "----------------------------------------------------------------"
echo "  CRIU Timing (from log):"
echo "    dump_one_task TOTAL:   ${DUMP_TOTAL}s"
echo "    parse_smaps:           ${PARSE_SMAPS}s"
echo "    dump_pages_seized:     ${DUMP_PAGES}s"
echo "    generate_vma_iovs:     ${GEN_IOVS}s"
echo "================================================================"

exit 0
