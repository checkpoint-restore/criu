#!/usr/bin/env bash
set -euo pipefail

# Restore script - run on REPLICA machine

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

FAST_CUTOVER=${FAST_CUTOVER:-0}
START_TOTAL=$(date +%s)
LOG_FILE="$IMAGES_DIR/lazy-primary.log"

apply_replica_gate() {
	sudo iptables -I INPUT 1 -p tcp --dport "$VALKEY_PORT" ! -s 127.0.0.1 -j REJECT 2>/dev/null || true
}

remove_replica_gate() {
	sudo iptables -D INPUT -p tcp --dport "$VALKEY_PORT" ! -s 127.0.0.1 -j REJECT 2>/dev/null || true
}

trap remove_replica_gate EXIT

echo "CRIU Restore - Replica Setup"
echo "  Listen IP  : $REPLICA_IP"
echo "  Port       : $CRIU_PORT"
echo "  Images Dir : $IMAGES_DIR"
echo "  Timeout    : ${WAIT_TIMEOUT}s"
echo "================================================================"

# Step 1: Kill valkey-server
echo "Step 1: Killing valkey-server"
sudo pkill -9 valkey-server 2>/dev/null || true
echo "valkey-server killed"

# Step 1b: Block remote access until replica role is configured
echo "Step 1b: Applying temporary replica network gate"
apply_replica_gate

# Step 2: Create ready signal for PRIMARY
echo "Step 2: Creating ready signal"
echo "READY" | sudo tee "$IMAGES_DIR/ready.log" >/dev/null
echo "Ready signal created at $IMAGES_DIR/ready.log"

# Step 3: Wait for PAGE SERVER READY TO SERVE
echo "Step 3: Waiting for page server..."
START_TIME=$(date +%s)
while true; do
  if [ -f "$LOG_FILE" ] && sudo grep -q "PAGE SERVER READY TO SERVE" "$LOG_FILE" 2>/dev/null; then
    echo "Page server ready!"
    break
  fi
  ELAPSED=$(($(date +%s) - START_TIME))
  if [ $ELAPSED -ge $WAIT_TIMEOUT ]; then
    echo "Timeout waiting for page server"
    exit 1
  fi
  sleep 0.5
done

# Step 4: Start wait_and_replicate.sh in background
echo "Step 4: Starting wait_and_replicate.sh in background"
"$SCRIPT_DIR/wait_and_replicate.sh" &
REPLICATE_PID=$!
echo "wait_and_replicate.sh started (PID: $REPLICATE_PID)"

# Step 5: Start CRIU lazy-pages daemon (connects to PRIMARY's page server)
echo "Step 5: Starting lazy-pages daemon (connecting to $PRIMARY_IP:$CRIU_PORT)"
sudo criu lazy-pages \
  --images-dir "$IMAGES_DIR" \
  --page-server \
  --address "$PRIMARY_IP" \
  --port "$CRIU_PORT" \
  --cow-dump \
  --tcp-close \
  -v1 -o "$IMAGES_DIR/lazy-server.log" &
LAZY_PAGES_PID=$!
echo "Lazy-pages daemon started (PID: $LAZY_PAGES_PID)"

# Sleep to let lazy-pages connect and be ready
sleep 1

# Step 6: Start CRIU restore (connects to local lazy-pages via Unix socket)
echo "Step 6: Starting CRIU restore"
RESTORE_ARGS=(
  --images-dir "$IMAGES_DIR"
  --lazy-pages
  --tcp-close
  --cow-dump
  --skip-file-rwx-check
)
if [ "$FAST_CUTOVER" = "1" ]; then
  RESTORE_ARGS+=(--leave-stopped)
fi
sudo criu restore \
  "${RESTORE_ARGS[@]}" \
  -v1 -o "$IMAGES_DIR/lazy-restore.log" &
RESTORE_PID=$!

VALKEY_PID=""
if [ "$FAST_CUTOVER" = "1" ]; then
  # Step 7: Wait for restored valkey process in stopped mode
  echo "Step 7: Waiting for valkey process (restored, stopped)..."
  for i in $(seq 1 120); do
    VALKEY_PID=$(pgrep -x valkey-server || true)
    if [ -n "$VALKEY_PID" ]; then
      echo "Valkey restored in stopped mode (PID: $VALKEY_PID)"
      break
    fi
    sleep 0.1
  done
  if [ -z "$VALKEY_PID" ]; then
    echo "ERROR: Valkey process not restored in FAST_CUTOVER mode"
    exit 1
  fi
else
  # Step 7: Wait for valkey to be responsive
  echo "Step 7: Waiting for valkey to be responsive..."
  for i in $(seq 1 60); do
    if valkey-cli ping &>/dev/null; then
      echo "Valkey is up"
      break
    fi
    sleep 0.5
  done
fi

# Step 8: Verify and summarize
echo "Step 8: Verifying restore..."
sleep 2

# Ensure replicaof setup finished before opening remote access
echo "Step 8b: Waiting for replica configuration task..."
if ! wait "$REPLICATE_PID"; then
	echo "ERROR: wait_and_replicate.sh failed"
	exit 1
fi
echo "Replica configuration completed"

echo "Step 8c: Removing temporary replica network gate"
remove_replica_gate

END_TOTAL=$(date +%s)
DURATION=$((END_TOTAL - START_TOTAL))

if [ "$FAST_CUTOVER" = "1" ]; then
  echo "================================================================"
  echo "Replica staged for fast cutover"
  echo "  Duration: ${DURATION}s"
  echo "  Valkey PID: $VALKEY_PID (stopped until PRIMARY sends SIGCONT)"
  echo "================================================================"
elif valkey-cli ping &>/dev/null; then
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
