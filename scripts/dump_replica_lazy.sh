#!/usr/bin/env bash
set -euo pipefail

# Configuration
DEST_IP="10.0.14.165"
PORT=9002
IMAGES_DIR="/fsx/lazy"
LOG_FILE="$IMAGES_DIR/lazy-primary.log"
READY_FILE="$IMAGES_DIR/ready.log"
WAIT_TIMEOUT=3000  # 50 minutes

echo "🔧 CRIU Dump Configuration"
echo "  Destination IP : $DEST_IP"
echo "  Port           : $PORT"
echo "  Images Dir     : $IMAGES_DIR"
echo "  Log File       : $LOG_FILE"
echo "  Ready Signal   : $READY_FILE"
echo "----------------------------------------------------------------"


echo "🧹 Step 1: Cleaning up $IMAGES_DIR/*"
sudo rm -rf "$IMAGES_DIR"/*
echo "✅ Cleanup complete"

# Wait for destination to be ready
echo "⏳ Waiting for destination ready signal at $READY_FILE"
START_TIME=$(date +%s)
while [ ! -f "$READY_FILE" ]; do
  ELAPSED=$(($(date +%s) - START_TIME))
  if [ $ELAPSED -ge $WAIT_TIMEOUT ]; then
    echo "❌ Timeout: Destination ready signal not found within ${WAIT_TIMEOUT}s"
    exit 1
  fi
  sleep 0.5
done
echo "✅ Destination is ready!"

# Get valkey-server PID
PID=$(pgrep -x valkey-server)
if [ -z "$PID" ]; then
  echo "❌ Error: valkey-server process not found"
  exit 1
fi

echo "✅ Found valkey-server PID: $PID"
echo "🚀 Starting CRIU dump with lazy-pages..."

# Execute CRIU dump command
sudo criu dump \
  --tree "$PID" \
  --images-dir "$IMAGES_DIR" \
  --cow-dump \
  --lazy-pages \
  --address "$DEST_IP" \
  --port "$PORT" \
  --tcp-close \
  --ext-unix-sk \
  -v2 -o "$LOG_FILE" \
  --leave-running


echo "✅ CRIU dump completed successfully"
echo "📋 Check log at: $LOG_FILE"
