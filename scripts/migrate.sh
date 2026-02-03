#!/usr/bin/env bash
set -euo pipefail

# Master script - run first

REPLICA_HOST="ec2-44-211-230-117.compute-1.amazonaws.com"
REPLICA_IP="172.31.15.117"
SSH_KEY="/home/ubuntu/.ssh/replica.pem"
SSH="ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"
IMAGES_DIR="/fsx/lazy"
PORT=9002
DATA_SIZE_GB=${1:-40}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# Step 1: Kill on both
log "Step 1: Kill processes..."
sudo pkill -9 valkey-server 2>/dev/null || true
sudo pkill -9 criu 2>/dev/null || true
$SSH ubuntu@$REPLICA_HOST "sudo systemctl stop valkey-server; sudo pkill -9 criu" 2>/dev/null || true
sleep 1

# Step 2: Start valkey on master
log "Step 2: Start valkey..."
valkey-server --daemonize yes --protected-mode no --save ""
sleep 2
PID=$(pgrep -x valkey-server)
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

# Step 4: Clean
log "Step 4: Clean $IMAGES_DIR..."
sudo rm -rf "$IMAGES_DIR"/*

# Step 5: Start replica restore in background
log "Step 5: Start replica..."
$SSH ubuntu@$REPLICA_HOST "sudo $SCRIPT_DIR/restore.sh" &
REPLICA_PID=$!

# Step 5b: Wait for replica ready signal
log "Step 5b: Wait for replica ready..."
READY_FILE="$IMAGES_DIR/ready.log"
for i in $(seq 1 60); do
  if [ -f "$READY_FILE" ]; then
    log "  Replica ready"
    break
  fi
  sleep 0.5
done

# Step 6: Dump
log "Step 6: CRIU dump..."
# Close userfaultfd fds if present - blocks CRIU dump
sudo gdb -p $PID -batch -ex "call close(12)" -ex "call close(13)" -ex detach -ex quit 2>/dev/null || true
sudo taskset -pc 0 $PID >/dev/null 2>&1 || true
# Pre-create log with world-readable permissions
sudo touch "$IMAGES_DIR/lazy-primary.log"
sudo chmod 644 "$IMAGES_DIR/lazy-primary.log"
sudo ASAN_OPTIONS=abort_on_error=1:disable_coredump=0:detect_leaks=0 \
     UBSAN_OPTIONS=halt_on_error=1 criu dump \
    --tree $PID \
    --images-dir "$IMAGES_DIR" \
    --cow-dump \
    --lazy-pages \
    --address "$REPLICA_IP" \
    --port $PORT \
    --tcp-close \
    --ext-unix-sk \
    --leave-running \
    -v2 -o "$IMAGES_DIR/lazy-primary.log" &
# Wait for dump to be ready
for i in $(seq 1 120); do
  if sudo grep -q "PAGE SERVER READY TO SERVE" "$IMAGES_DIR/lazy-primary.log" 2>/dev/null; then
    log "  Dump ready"
    break
  fi
  sleep 0.5
done

# Step 7: Wait for replica
log "Step 7: Wait for replica..."
wait $REPLICA_PID || true

# Step 8: Check
log "Step 8: Check replica..."
sleep 3
REPLICA_MEM=$($SSH ubuntu@$REPLICA_HOST "valkey-cli info memory | grep used_memory_human | cut -d: -f2 | tr -d '\r'" 2>/dev/null || echo "?")

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
