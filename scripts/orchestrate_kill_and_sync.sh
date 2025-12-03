#!/usr/bin/env bash
set -euo pipefail

# Configuration
SOURCE_HOST="ec2-54-221-42-237.compute-1.amazonaws.com"
SOURCE_USER="ubuntu"
SOURCE_SCRIPT="/home/ubuntu/work/valkey/scripts_criu/dump_replica_lazy.sh"
DEST_IP="10.0.14.165"
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
rm /var/log/valkey/stdout.log
rm /var/log/valkey/stderr.log
touch /var/log/valkey/stderr.log
touch /var/log/valkey/stdout.log
echo "✅ Cleanup complete"

# Step 2: Kill valkey-server
echo "🔪 Step 2: Killing valkey-server"
sudo pkill -9 valkey-server || true
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
  if [ -f "$LOG_FILE" ] && grep -q "PAGE SERVER READY TO SERVE" "$LOG_FILE"; then
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

# Step 6: Start CRIU lazy-pages page server in background
echo "🌐 Step 6: Starting CRIU lazy-pages page server"
sudo criu lazy-pages \
  --images-dir "$IMAGES_DIR" \
  --page-server \
  --address "$DEST_IP" \
  --port "$PORT" \
  --tcp-close \
  --cow-dump \
  -v2 -o "$IMAGES_DIR/lazy-server.log" &
PAGE_SERVER_PID=$!
echo "✅ Page server started (PID: $PAGE_SERVER_PID)"

# Sleep before restore
echo "⏸️  Sleeping 0.3 seconds..."
sleep 0.3

# Step 7: Start CRIU restore
echo "📦 Step 7: Starting CRIU restore"
sudo criu restore \
  --images-dir "$IMAGES_DIR" \
  --lazy-pages \
  --tcp-close \
  --cow-dump \
  --skip-file-rwx-check \
  -v2 -o "$IMAGES_DIR/lazy-restore.log"

echo "================================================================"
echo "✅ Orchestration completed successfully!"
echo "📋 Logs available at:"
echo "   - Source dump:  $LOG_FILE (on source machine)"
echo "   - Page server:  $IMAGES_DIR/lazy-server.log"
echo "   - Restore:      $IMAGES_DIR/lazy-restore.log"
