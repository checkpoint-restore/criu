#!/usr/bin/env bash
set -euo pipefail

# Configuration
SOURCE_HOST="ec2-54-221-42-237.compute-1.amazonaws.com"
SOURCE_USER="ubuntu"
SOURCE_SCRIPT="/home/ubuntu/work/scripts/dump_replica_lazy.sh"
DEST_IP="172.31.15.117"
PORT=9002
IMAGES_DIR="/fsx/lazy"
LOG_FILE="$IMAGES_DIR/lazy-primary.log"
WAIT_TIMEOUT=300  # 5 minutes
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 Starting Kill & Sync Orchestration"
echo "  Source Host    : $SOURCE_HOST"
echo "  Destination IP : $DEST_IP"
echo "  Port           : $PORT"
echo "  Images Dir     : $IMAGES_DIR"
echo "  Timeout        : ${WAIT_TIMEOUT}s"
echo "================================================================"

# Step 1: Clean up /fsx/lazy/*
echo "🧹 Step 1: Cleaning up $IMAGES_DIR/*"
sudo rm -rf "$IMAGES_DIR"/*
echo "✅ Cleanup complete"

# Step 2: Kill valkey-server process
echo "🔪 Step 2: Killing valkey-server process"
sudo pkill -9 valkey-server 2>/dev/null || true
sleep 0.5
echo "✅ valkey-server killed"

# Step 3: Start wait_and_replicate.sh in background
echo "🔄 Step 3: Starting wait_and_replicate.sh in background"
"$SCRIPT_DIR/wait_and_replicate.sh" &
REPLICATE_PID=$!
echo "✅ wait_and_replicate.sh started (PID: $REPLICATE_PID)"

# Step 4: Signal source machine that destination is ready
echo "🚦 Step 4: Creating ready signal for source machine"
echo "READY" | sudo tee "$IMAGES_DIR/ready.log" >/dev/null
echo "✅ Ready signal created at $IMAGES_DIR/ready.log"
echo "   Source machine can now start the dump process"

# Step 5: Wait for "PAGE SERVER READY TO SERVE" in log file
echo "⏳ Step 5: Waiting for 'PAGE SERVER READY TO SERVE' in $LOG_FILE"
START_TIME=$(date +%s)
while true; do
  if [ -f "$LOG_FILE" ] && sudo grep -q "PAGE SERVER READY TO SERVE" "$LOG_FILE" 2>/dev/null; then
    echo "✅ Page server ready signal detected"
    break
  fi
  
  ELAPSED=$(($(date +%s) - START_TIME))
  if [ $ELAPSED -ge $WAIT_TIMEOUT ]; then
    echo "❌ Timeout: Did not find 'PAGE SERVER READY TO SERVE' within ${WAIT_TIMEOUT}s"
    exit 1
  fi
  
  sleep 0.5
done

# Step 6: Start CRIU lazy-pages daemon in background
echo "🌐 Step 6: Starting CRIU lazy-pages daemon"
sudo criu lazy-pages \
  --images-dir "$IMAGES_DIR" \
  --page-server \
  --address "$DEST_IP" \
  --port "$PORT" \
  --tcp-close \
  -v2 -o "$IMAGES_DIR/lazy-server.log" &
PAGE_SERVER_PID=$!
echo "✅ lazy-pages daemon started (PID: $PAGE_SERVER_PID)"

# Sleep before restore to ensure lazy-pages is ready
echo "⏸️  Sleeping 1 second..."
sleep 1

# Step 7: Start CRIU restore
echo "📦 Step 7: Starting CRIU restore"
sudo criu restore \
  --images-dir "$IMAGES_DIR" \
  --lazy-pages \
  --tcp-close \
  --skip-file-rwx-check \
  -v2 -o "$IMAGES_DIR/lazy-restore.log"

echo "================================================================"
echo "✅ Orchestration completed successfully!"
echo "📋 Logs available at:"
echo "   - Source dump:  $LOG_FILE (on source machine)"
echo "   - Page server:  $IMAGES_DIR/lazy-server.log"
echo "   - Restore:      $IMAGES_DIR/lazy-restore.log"
