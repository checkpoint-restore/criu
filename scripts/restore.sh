#!/usr/bin/env bash
set -euo pipefail

START_TOTAL=$(date +%s)

# Configuration
DEST_IP="172.31.15.117"
PORT=9002
IMAGES_DIR="/fsx/lazy"
LOG_FILE="$IMAGES_DIR/lazy-primary.log"
WAIT_TIMEOUT=300  # 5 minutes
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting Kill & Sync Orchestration"
echo "  Destination IP : $DEST_IP"
echo "  Port           : $PORT"
echo "  Images Dir     : $IMAGES_DIR"
echo "  Timeout        : ${WAIT_TIMEOUT}s"
echo "================================================================"

# Step 1: Clean up /fsx/lazy/*
echo "Step 1: Cleaning up $IMAGES_DIR/*"
sudo rm -rf "$IMAGES_DIR"/*
sudo rm -f /var/log/valkey/stdout.log 2>/dev/null || true
sudo rm -f /var/log/valkey/stderr.log 2>/dev/null || true
sudo touch /var/log/valkey/stderr.log 2>/dev/null || true
sudo touch /var/log/valkey/stdout.log 2>/dev/null || true
echo "Cleanup complete"

# Step 2: Kill valkey-server
echo "Step 2: Killing valkey-server"
sudo systemctl stop valkey-server 2>/dev/null || true
sudo pkill -9 valkey-server 2>/dev/null || true
echo "valkey-server killed"

# Step 3: Start wait_and_replicate.sh in background
echo "Step 3: Starting wait_and_replicate.sh in background"
"$SCRIPT_DIR/wait_and_replicate.sh" &
REPLICATE_PID=$!
echo "wait_and_replicate.sh started (PID: $REPLICATE_PID)"

# Step 4: Signal source machine that destination is ready
echo "Step 4: Creating ready signal for source machine"
echo "READY" | sudo tee "$IMAGES_DIR/ready.log" >/dev/null
echo "Ready signal created at $IMAGES_DIR/ready.log"

# Step 5: Wait for "PAGE SERVER READY TO SERVE" in log file
echo "Step 5: Waiting for 'PAGE SERVER READY TO SERVE' in $LOG_FILE"
START_TIME=$(date +%s)
while true; do
  if [ -f "$LOG_FILE" ] && sudo grep -q "PAGE SERVER READY TO SERVE" "$LOG_FILE"; then
    echo "Page server ready signal detected"
    break
  fi

  ELAPSED=$(($(date +%s) - START_TIME))
  if [ $ELAPSED -ge $WAIT_TIMEOUT ]; then
    echo "Timeout: Did not find 'PAGE SERVER READY TO SERVE' within ${WAIT_TIMEOUT}s"
    exit 1
  fi

  sleep 0.5
done

# Step 6: Start CRIU lazy-pages page server in background
echo "Step 6: Starting CRIU lazy-pages page server"
sudo criu lazy-pages \
  --images-dir "$IMAGES_DIR" \
  --page-server \
  --address "$DEST_IP" \
  --port "$PORT" \
  --cow-dump \
  --tcp-close \
  -v1 -o "$IMAGES_DIR/lazy-server.log" &
PAGE_SERVER_PID=$!
echo "Page server started (PID: $PAGE_SERVER_PID)"

# Sleep before restore
echo "Sleeping 0.3 seconds..."
sleep 0.3

# Step 7: Start CRIU restore (background - stays running for lazy pages)
echo "Step 7: Starting CRIU restore"
sudo criu restore \
  --images-dir "$IMAGES_DIR" \
  --lazy-pages \
  --tcp-close \
  --cow-dump \
  --skip-file-rwx-check \
  -v1 -o "$IMAGES_DIR/lazy-restore.log" &
RESTORE_PID=$!

# Wait for valkey to be responsive (restore completes quickly, but criu stays running)
echo "Waiting for valkey to be responsive..."
for i in $(seq 1 60); do
  if valkey-cli ping &>/dev/null; then
    echo "Valkey is up"
    break
  fi
  sleep 0.5
done

# Step 8: Verify and summarize
echo "Step 8: Verifying restore..."
sleep 2

END_TOTAL=$(date +%s)
DURATION=$((END_TOTAL - START_TOTAL))

if valkey-cli ping &>/dev/null; then
  MEM=$(valkey-cli info memory | grep used_memory_human | cut -d: -f2 | tr -d '\r')
  KEYS=$(valkey-cli dbsize | cut -d: -f2 | tr -d '\r' 2>/dev/null || valkey-cli dbsize)
  echo "================================================================"
  echo "Migration completed successfully!"
  echo "  Duration: ${DURATION}s"
  echo "  Memory:   $MEM"
  echo "  Keys:     $KEYS"
  echo "================================================================"
else
  echo "ERROR: Valkey not responding after restore"
  exit 1
fi

exit 0
