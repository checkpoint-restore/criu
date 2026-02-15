#!/usr/bin/env bash
set -euo pipefail

# Master migration script - run on PRIMARY machine

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

DATA_SIZE_GB=${1:-$DEFAULT_DATA_SIZE_GB}
DEFAULT_CRIU_BIN="$SCRIPT_DIR/../criu/criu"
if [ -x "$DEFAULT_CRIU_BIN" ]; then
	CRIU_BIN=${CRIU_BIN:-$DEFAULT_CRIU_BIN}
else
	CRIU_BIN=${CRIU_BIN:-criu}
fi
FAST_CUTOVER=${FAST_CUTOVER:-0}
CUTOVER_PAUSE_MS=${CUTOVER_PAUSE_MS:-50}
RUN_WORKLOAD_DURING_MIGRATION=${RUN_WORKLOAD_DURING_MIGRATION:-0}
KEEP_SOURCE_RUNNING=${KEEP_SOURCE_RUNNING:-0}
SKIP_FILL=${SKIP_FILL:-0}
STOP_DUMP_ON_COMPLETE=${STOP_DUMP_ON_COMPLETE:-1}
WORKLOAD_KEYSPACE=${WORKLOAD_KEYSPACE:-1000000}
WORKLOAD_CLIENTS=${WORKLOAD_CLIENTS:-64}
WORKLOAD_PIPELINE=${WORKLOAD_PIPELINE:-16}
# Default to 64KB so the live workload does not shrink the 64KB-filled dataset.
WORKLOAD_DATA_SIZE=${WORKLOAD_DATA_SIZE:-64000}
WORKLOAD_LOG_FILE=${WORKLOAD_LOG_FILE:-}
CRIU_DUMP_STRACE_OUT=${CRIU_DUMP_STRACE_OUT:-}
CUTOVER_MARKER_FILE=${CUTOVER_MARKER_FILE:-}
REPLICA_PING_POLL_INTERVAL_S=${REPLICA_PING_POLL_INTERVAL_S:-0.01}
VALKEY_CMD_TIMEOUT_S=${VALKEY_CMD_TIMEOUT_S:-2}
POST_REPLICA_SYNC_CHECK=${POST_REPLICA_SYNC_CHECK:-0}
CUTOVER_GATE_EVENT_WAIT_S=${CUTOVER_GATE_EVENT_WAIT_S:-15}
SSH="ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"
REPLICA_SSH_HOST="${REPLICA_IP:-$REPLICA_HOST}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

valkey_cmd()
{
	timeout "${VALKEY_CMD_TIMEOUT_S}s" valkey-cli -h 127.0.0.1 -p "$VALKEY_PORT" "$@"
}

valkey_ping_ok()
{
	valkey_cmd ping &>/dev/null
}

mark_cutover_event() {
  local event="$1"
  local ts_ms

  if [ -z "$CUTOVER_MARKER_FILE" ]; then
    return 0
  fi

  ts_ms=$(date +%s%3N)
  mkdir -p "$(dirname "$CUTOVER_MARKER_FILE")" 2>/dev/null || true
  if ! printf "%s %s %s\n" "$event" "$ts_ms" "PRIMARY" | tee -a "$CUTOVER_MARKER_FILE" >/dev/null 2>&1; then
    printf "%s %s %s\n" "$event" "$ts_ms" "PRIMARY" | sudo tee -a "$CUTOVER_MARKER_FILE" >/dev/null 2>&1 || true
  fi
}

stop_workload() {
	if [ -n "${WORKLOAD_PID:-}" ]; then
		kill "$WORKLOAD_PID" 2>/dev/null || true
		WORKLOAD_PID=""
	fi
	sudo pkill -9 valkey-benchmark 2>/dev/null || true
}

# Step 1: Kill on both
log "Step 1: Kill processes..."
if [ "$KEEP_SOURCE_RUNNING" = "1" ] || [ "$SKIP_FILL" = "1" ]; then
  if [ "$SKIP_FILL" = "1" ] && [ "$KEEP_SOURCE_RUNNING" != "1" ]; then
    log "  SKIP_FILL=1 requires preserving source dataset; keeping source valkey-server running"
  else
    log "  Keeping source valkey-server running"
  fi
else
  sudo pkill -9 valkey-server 2>/dev/null || true
fi
sudo pkill -9 valkey-benchmark 2>/dev/null || true
sudo pkill -9 criu 2>/dev/null || true
$SSH ubuntu@$REPLICA_SSH_HOST "sudo pkill -9 valkey-server || true; sudo pkill -9 criu || true; sudo pkill -9 -f '[/]scripts/restore.sh' || true; sudo pkill -9 -f '[c]riu lazy-pages' || true; while sudo iptables -C INPUT -p tcp --dport $VALKEY_PORT ! -s 127.0.0.1 -j REJECT 2>/dev/null; do sudo iptables -D INPUT -p tcp --dport $VALKEY_PORT ! -s 127.0.0.1 -j REJECT || true; done" 2>/dev/null || true
sleep 1

# Step 2: Wait for valkey to be running and responsive on master
log "Step 2: Check valkey..."
PID=""
for i in $(seq 1 240); do
  PID=$(pgrep -x valkey-server || true)
  if [ -n "$PID" ]; then
    break
  fi
  sleep 0.5
done
if [ -z "$PID" ]; then
  log "ERROR: valkey-server not running"
  exit 1
fi
log "  PID: $PID"
for i in $(seq 1 40); do
  if valkey_ping_ok; then
    break
  fi
  sleep 0.25
done
if ! valkey_ping_ok; then
  log "ERROR: valkey-server not responding on port $VALKEY_PORT"
  exit 1
fi

# Step 3: Fill using valkey-benchmark
# Empirical: ~25300 keys per GB with 64KB values (includes overhead)
NUM_KEYS=$((DATA_SIZE_GB * 25300))
NUM_OPS=$((NUM_KEYS + 50000))
if [ "$SKIP_FILL" = "1" ]; then
  log "Step 3: Skip fill (SKIP_FILL=1)"
else
  log "Step 3: Fill ~${DATA_SIZE_GB}GB using valkey-benchmark..."
  log "  Keys: $NUM_KEYS, Ops: $NUM_OPS, Value size: 64KB"
  valkey-benchmark -h 127.0.0.1 -p "$VALKEY_PORT" -t set -d 64000 -r $NUM_KEYS -n $NUM_OPS --threads 10 -q
fi
MEM=$(valkey_cmd info memory 2>/dev/null | grep used_memory_human | cut -d: -f2 | tr -d '\r')
if [ -z "${MEM:-}" ]; then
  MEM="unknown"
fi
log "  Memory: $MEM"

# Step 4: Clean images dir
log "Step 4: Clean $IMAGES_DIR..."
sudo rm -rf "$IMAGES_DIR"/*

# Step 5: Start replica FIRST (it will create ready signal and wait)
log "Step 5: Start replica (will wait for page server)..."
REMOTE_RESTORE_ENV=("CUTOVER_MARKER_FILE='$CUTOVER_MARKER_FILE'")
if [ "$FAST_CUTOVER" = "1" ]; then
  REMOTE_RESTORE_ENV+=("FAST_CUTOVER=1" "CUTOVER_PAUSE_MS='$CUTOVER_PAUSE_MS'")
fi
for env_key in \
  WAIT_REPLICA_ROLE_ACTIVE \
  WAIT_REPLICA_LINK_UP \
  REPLICA_POLL_INTERVAL_S \
  RESTORE_MAX_PING_ATTEMPTS \
  RESTORE_PING_INTERVAL_S \
  RESTORE_WRITE_GUARD_ATTEMPTS \
  RESTORE_WRITE_GUARD_INTERVAL_S; do
  env_val="${!env_key:-}"
  if [ -n "$env_val" ]; then
    REMOTE_RESTORE_ENV+=("$env_key='$env_val'")
  fi
done
$SSH ubuntu@$REPLICA_SSH_HOST "sudo env ${REMOTE_RESTORE_ENV[*]} $SCRIPT_DIR/restore.sh" &
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
if [ ! -f "$READY_FILE" ]; then
  log "ERROR: replica ready signal not found at $READY_FILE"
  exit 1
fi

# Step 6: NOW start CRIU dump (replica is waiting for page server)
log "Step 6: CRIU dump..."
PID=""
for i in $(seq 1 40); do
  PID=$(pgrep -x valkey-server || true)
  if [ -n "$PID" ] && valkey_ping_ok; then
    break
  fi
  sleep 0.25
done
if [ -z "$PID" ]; then
  log "ERROR: valkey-server PID not found before dump"
  exit 1
fi
log "  Dump PID: $PID"
sudo touch "$IMAGES_DIR/lazy-primary.log"
sudo chmod 644 "$IMAGES_DIR/lazy-primary.log"
# Run dump - cow-dump keeps running, we'll kill it after restore.
# Optional syscall profiling can be enabled via CRIU_DUMP_STRACE_OUT.
CRIU_DUMP_CMD=(
  sudo "$CRIU_BIN" dump
  --tree "$PID"
  --images-dir "$IMAGES_DIR"
  --cow-dump
  --lazy-pages
  --address "$PRIMARY_IP"
  --port "$CRIU_PORT"
  --tcp-close
  --ext-unix-sk
  --leave-running
  -v2 -o "$IMAGES_DIR/lazy-primary.log"
)

if [ -n "$CRIU_DUMP_STRACE_OUT" ]; then
  log "  Enabling dump strace: $CRIU_DUMP_STRACE_OUT"
  CRIU_DUMP_CMD=(
    sudo strace -ff -yy -tt -T -o "$CRIU_DUMP_STRACE_OUT"
    "$CRIU_BIN" dump
    --tree "$PID"
    --images-dir "$IMAGES_DIR"
    --cow-dump
    --lazy-pages
    --address "$PRIMARY_IP"
    --port "$CRIU_PORT"
    --tcp-close
    --ext-unix-sk
    --leave-running
    -v2 -o "$IMAGES_DIR/lazy-primary.log"
  )
fi

"${CRIU_DUMP_CMD[@]}" &
DUMP_PID=$!

sleep 2
if ! kill -0 "$DUMP_PID" 2>/dev/null; then
  log "ERROR: criu dump exited early"
  sudo tail -n 120 "$IMAGES_DIR/lazy-primary.log" || true
  exit 1
fi

WORKLOAD_PID=""
if [ "$RUN_WORKLOAD_DURING_MIGRATION" = "1" ]; then
  log "Step 6b: Start workload traffic..."
  if [ -z "$WORKLOAD_LOG_FILE" ]; then
    WORKLOAD_LOG_FILE=$(mktemp /tmp/migrate_workload_live.XXXXXX.log 2>/dev/null || echo "/tmp/migrate_workload_live.log")
  fi
  if ! touch "$WORKLOAD_LOG_FILE" 2>/dev/null; then
    WORKLOAD_LOG_FILE="/dev/null"
  fi
  valkey-benchmark -h 127.0.0.1 -p "$VALKEY_PORT" \
    -t set,get \
    -r "$WORKLOAD_KEYSPACE" \
    -c "$WORKLOAD_CLIENTS" \
    -P "$WORKLOAD_PIPELINE" \
    -d "$WORKLOAD_DATA_SIZE" \
    -n 1000000000 \
    -q >"$WORKLOAD_LOG_FILE" 2>&1 &
  WORKLOAD_PID=$!
  log "  Workload PID: $WORKLOAD_PID"
  log "  Workload log: $WORKLOAD_LOG_FILE"
  sleep 1
  if ! kill -0 "$WORKLOAD_PID" 2>/dev/null; then
    log "ERROR: workload process exited early"
    if [ "$WORKLOAD_LOG_FILE" != "/dev/null" ]; then
      tail -n 40 "$WORKLOAD_LOG_FILE" 2>/dev/null || true
    fi
    exit 1
  fi
fi

# Step 7: Wait for replica readiness without blocking on ssh wrapper process
log "Step 7: Wait for replica readiness..."

# In normal mode, count cutover only after the replica gate is lifted
# (shared marker file path required so both hosts can write/read it).
if [ "$FAST_CUTOVER" != "1" ] && [ -n "$CUTOVER_MARKER_FILE" ] && [[ "$CUTOVER_MARKER_FILE" == "$IMAGES_DIR/"* ]]; then
  log "Step 7a: Waiting for replica gate removal marker..."
  GATE_REMOVED=0
  for _ in $(seq 1 $((CUTOVER_GATE_EVENT_WAIT_S * 20))); do
    if grep -q "^REPLICA_GATE_REMOVED " "$CUTOVER_MARKER_FILE" 2>/dev/null; then
      GATE_REMOVED=1
      break
    fi
    sleep 0.05
  done
  if [ "$GATE_REMOVED" -eq 1 ]; then
    log "  Replica gate removed marker detected"
  else
    log "  WARN: replica gate removal marker not observed before cutover timing"
  fi
fi

# Step 8: Cutover/check
REPLICA_UP=0
mark_cutover_event "CUTOVER_START_MS"
if [ "$FAST_CUTOVER" = "1" ]; then
  log "Step 8: Fast cutover (pause ${CUTOVER_PAUSE_MS}ms writes, freeze source, resume replica)..."
  valkey_cmd CLIENT PAUSE "$CUTOVER_PAUSE_MS" WRITE >/dev/null 2>&1 || true
  sudo pkill -STOP -x valkey-server 2>/dev/null || true
  $SSH ubuntu@$REPLICA_SSH_HOST "sudo pkill -CONT -x valkey-server" >/dev/null 2>&1 || true
else
  log "Step 8: Check replica..."
fi
for i in $(seq 1 120); do
  if $SSH ubuntu@$REPLICA_SSH_HOST "timeout ${VALKEY_CMD_TIMEOUT_S}s valkey-cli ping >/dev/null 2>&1"; then
    REPLICA_UP=1
    mark_cutover_event "CUTOVER_END_MS"
    break
  fi
  sleep "$REPLICA_PING_POLL_INTERVAL_S"
done
if [ "$REPLICA_UP" -ne 1 ]; then
  log "ERROR: replica valkey is not responding"
  log "Step 8b: Stop dump process..."
  sudo pkill -9 -f "[c]riu dump" 2>/dev/null || true
  sleep 1
  if [ -n "$WORKLOAD_PID" ]; then
    log "Step 8c: Stop workload traffic..."
    kill "$WORKLOAD_PID" 2>/dev/null || true
    sudo pkill -9 valkey-benchmark 2>/dev/null || true
  fi
  if kill -0 "$REPLICA_PID" 2>/dev/null; then
    kill "$REPLICA_PID" 2>/dev/null || true
    wait "$REPLICA_PID" 2>/dev/null || true
  fi
  if [ "$FAST_CUTOVER" = "1" ]; then
    log "Recovering source from STOP state"
    sudo pkill -CONT -x valkey-server 2>/dev/null || true
  fi
  exit 1
fi

REPLICA_SYNCED=0
if [ "$POST_REPLICA_SYNC_CHECK" = "1" ]; then
  for i in $(seq 1 120); do
    if $SSH ubuntu@$REPLICA_SSH_HOST "timeout ${VALKEY_CMD_TIMEOUT_S}s valkey-cli info replication | awk -F: '/^role:/ {role=\$2} /^master_link_status:/ {link=\$2} END {gsub(/\r/, \"\", role); gsub(/\r/, \"\", link); if ((role == \"slave\" || role == \"replica\") && link == \"up\") exit 0; exit 1}'" >/dev/null 2>&1; then
      REPLICA_SYNCED=1
      break
    fi
    sleep 0.25
  done
if [ "$REPLICA_SYNCED" -ne 1 ]; then
    log "ERROR: replica did not reach role=replica/slave with master_link_status=up"
    log "Step 8b: Stop dump process..."
    sudo pkill -9 -f "[c]riu dump" 2>/dev/null || true
    sleep 1
    stop_workload
    if kill -0 "$REPLICA_PID" 2>/dev/null; then
      kill "$REPLICA_PID" 2>/dev/null || true
      wait "$REPLICA_PID" 2>/dev/null || true
    fi
    if [ "$FAST_CUTOVER" = "1" ]; then
      log "Recovering source from STOP state"
      sudo pkill -CONT -x valkey-server 2>/dev/null || true
    fi
    exit 1
  fi
else
  log "Step 8a: Skip post-cutover replication-link check (POST_REPLICA_SYNC_CHECK=0)"
fi

# Step 8b: Optionally stop dump/page-server process
if [ "$STOP_DUMP_ON_COMPLETE" = "1" ]; then
  log "Step 8b: Stop dump process..."
  sudo pkill -9 -f "[c]riu dump" 2>/dev/null || true
  sleep 1
else
  log "Step 8b: Keep dump process running (STOP_DUMP_ON_COMPLETE=0)"
fi

if [ -n "$WORKLOAD_PID" ]; then
  log "Step 8c: Stop workload traffic..."
  stop_workload
fi

wait "$REPLICA_PID" 2>/dev/null || true

REPLICA_MEM=$($SSH ubuntu@$REPLICA_SSH_HOST "timeout ${VALKEY_CMD_TIMEOUT_S}s valkey-cli info memory | grep used_memory_human | cut -d: -f2 | tr -d '\r'" 2>/dev/null || echo "?")

# Extract CRIU timing from logs
LOG_FILE="$IMAGES_DIR/lazy-primary.log"
DUMP_TOTAL=$(sudo grep -a "dump_one_task TOTAL" "$LOG_FILE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' || echo "?")
PARSE_SMAPS=$(sudo grep -a "parse_smaps took" "$LOG_FILE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' || echo "?")
DUMP_PAGES=$(sudo grep -a "parasite_dump_pages_seized took" "$LOG_FILE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' || echo "?")
GEN_IOVS=$(sudo grep -a "generate_vma_iovs loop" "$LOG_FILE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' || echo "?")

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
