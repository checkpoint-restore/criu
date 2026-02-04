#!/usr/bin/env bash
set -euo pipefail

# Master migration script - run on PRIMARY machine

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

DATA_SIZE_GB=${1:-$DEFAULT_DATA_SIZE_GB}
SSH="ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"
REPLICA_SSH_HOST="${REPLICA_IP:-$REPLICA_HOST}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# Step 1: Kill on both
log "Step 1: Kill processes..."
sudo pkill -9 valkey-server 2>/dev/null || true
sudo pkill -9 criu 2>/dev/null || true
$SSH ubuntu@$REPLICA_SSH_HOST "sudo systemctl stop valkey-server; sudo pkill -9 criu" 2>/dev/null || true
sleep 1

# Step 2: Start valkey on master
log "Step 2: Start valkey..."
valkey-server --daemonize yes --protected-mode no --save ""
PID=""
for i in $(seq 1 20); do
  PID=$(pgrep -x valkey-server || true)
  if [ -n "$PID" ]; then
    break
  fi
  sleep 0.5
done
if [ -z "$PID" ]; then
  log "ERROR: valkey-server failed to start"
  exit 1
fi
log "  PID: $PID"

# Step 3: Fill using valkey-benchmark
# Empirical: ~25300 keys per GB with 64KB values (includes overhead)
NUM_KEYS=$((DATA_SIZE_GB * 25300))
NUM_OPS=$((NUM_KEYS + 50000))
log "Step 3: Fill ~${DATA_SIZE_GB}GB using valkey-benchmark..."
log "  Keys: $NUM_KEYS, Ops: $NUM_OPS, Value size: 64KB"
valkey-benchmark -t set -d 64000 -r $NUM_KEYS -n $NUM_OPS --threads 10 -q
MEM=$(valkey-cli info memory | grep used_memory_human | cut -d: -f2 | tr -d '\r')
log "  Memory: $MEM"

# Step 4: Clean images dir
log "Step 4: Clean $IMAGES_DIR..."
sudo rm -rf "$IMAGES_DIR"/*

# Step 5: Start replica FIRST (it will create ready signal and wait)
# Use timeout to ensure it doesn't hang forever
log "Step 5: Start replica (will wait for page server)..."
# Timeout scales with data size: base 15s + 1s per GB
TIMEOUT=$((15 + DATA_SIZE_GB))
timeout $TIMEOUT $SSH ubuntu@$REPLICA_SSH_HOST "sudo $SCRIPT_DIR/restore.sh" &
REPLICA_PID=$!

# Step 5b: Wait for replica ready signal
log "Step 5b: Wait for replica ready signal..."
READY_FILE="$IMAGES_DIR/ready.log"
for i in $(seq 1 60); do
  if [ -f "$READY_FILE" ]; then
    log "  Replica ready"
    break
  fi
  sleep 0.5
done

# Step 6: NOW start CRIU dump (replica is waiting for page server)
log "Step 6: CRIU dump..."
sudo gdb -p $PID -batch -ex "call close(12)" -ex "call close(13)" -ex detach -ex quit 2>/dev/null || true
sudo taskset -pc 0 $PID >/dev/null 2>&1 || true
sudo touch "$IMAGES_DIR/lazy-primary.log"
sudo chmod 644 "$IMAGES_DIR/lazy-primary.log"
# Run dump with timeout - cow-dump keeps running, we'll kill it after restore
timeout $TIMEOUT sudo criu dump \
    --tree $PID \
    --images-dir "$IMAGES_DIR" \
    --cow-dump \
    --lazy-pages \
    --address "$PRIMARY_IP" \
    --port $CRIU_PORT \
    --tcp-close \
    --ext-unix-sk \
    --leave-running \
    -v2 -o "$IMAGES_DIR/lazy-primary.log" &
DUMP_PID=$!

# Step 7: Wait for replica to complete
log "Step 7: Wait for replica..."
wait $REPLICA_PID || true

# Step 7b: Kill dump process (cow-dump keeps running forever with --leave-running)
log "Step 7b: Stop dump process..."
sudo pkill -9 -f "criu dump" 2>/dev/null || true
sleep 1

# Step 8: Check
log "Step 8: Check replica..."
sleep 3
REPLICA_MEM=$($SSH ubuntu@$REPLICA_SSH_HOST "valkey-cli info memory | grep used_memory_human | cut -d: -f2 | tr -d '\r'" 2>/dev/null || echo "?")

# Extract CRIU timing from logs
LOG_FILE="$IMAGES_DIR/lazy-primary.log"
DUMP_TOTAL=$(sudo grep "dump_one_task TOTAL" "$LOG_FILE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' || echo "?")
PARSE_SMAPS=$(sudo grep "parse_smaps took" "$LOG_FILE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' || echo "?")
DUMP_PAGES=$(sudo grep "parasite_dump_pages_seized took" "$LOG_FILE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' || echo "?")
GEN_IOVS=$(sudo grep "generate_vma_iovs loop" "$LOG_FILE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' || echo "?")

log "================================================================"
log "Migration complete!"
log "  Source Memory:   $MEM"
log "  Replica Memory:  $REPLICA_MEM"
log "----------------------------------------------------------------"
log "  CRIU Timing (dump):"
log "    dump_one_task TOTAL:   ${DUMP_TOTAL}s"
log "    parse_smaps:           ${PARSE_SMAPS}s"
log "    dump_pages_seized:     ${DUMP_PAGES}s"
log "    generate_vma_iovs:     ${GEN_IOVS}s"
log "================================================================"
