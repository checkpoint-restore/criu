#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Restore script — run on REPLICA machine
#
# Orchestrates the replica side of a CRIU COW live migration:
#   1. Kills any existing valkey, applies a network gate
#   2. Signals readiness to the primary
#   3. Waits for the source dump/page-server to be ready
#   4. Starts lazy-pages daemon + CRIU restore (with retry)
#   5. Waits for the restored process, configures replication
#   6. Verifies write protection, removes network gate
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

# --- Configuration defaults (all overridable via environment) ----------------
FAST_CUTOVER=${FAST_CUTOVER:-0}
DEFAULT_CRIU_BIN="$SCRIPT_DIR/../criu/criu"
if [ -x "$DEFAULT_CRIU_BIN" ]; then
	CRIU_BIN=${CRIU_BIN:-$DEFAULT_CRIU_BIN}
else
	CRIU_BIN=${CRIU_BIN:-criu}
fi
START_TOTAL=$(date +%s)
LOG_FILE="$IMAGES_DIR/lazy-primary.log"
CUTOVER_MARKER_FILE=${CUTOVER_MARKER_FILE:-}
RESTORE_VERIFY_DELAY_S=${RESTORE_VERIFY_DELAY_S:-0}
RESTORE_MAX_PING_ATTEMPTS=${RESTORE_MAX_PING_ATTEMPTS:-600}
RESTORE_PING_INTERVAL_S=${RESTORE_PING_INTERVAL_S:-0.05}
RESTORE_WRITE_GUARD_ATTEMPTS=${RESTORE_WRITE_GUARD_ATTEMPTS:-2000}
RESTORE_WRITE_GUARD_INTERVAL_S=${RESTORE_WRITE_GUARD_INTERVAL_S:-0.01}
RESTORE_RETRY_ATTEMPTS=${RESTORE_RETRY_ATTEMPTS:-200}
RESTORE_RETRY_INTERVAL_S=${RESTORE_RETRY_INTERVAL_S:-0.2}
PAGE_SERVER_READY_PATTERN=${PAGE_SERVER_READY_PATTERN:-PAGE SERVER READY TO SERVE}

# --- Helpers -----------------------------------------------------------------

# Write a timestamped phase event to the shared cutover marker file.
# Used by the traffic harness and migrate.sh for timing analysis.
mark_phase_event() {
	local event="$1"
	local ts_ms

	if [ -z "$CUTOVER_MARKER_FILE" ]; then
		return 0
	fi

	ts_ms=$(date +%s%3N)
	mkdir -p "$(dirname "$CUTOVER_MARKER_FILE")" 2>/dev/null || true
	printf "%s %s %s\n" "$event" "$ts_ms" "REPLICA_RESTORE" >>"$CUTOVER_MARKER_FILE" 2>/dev/null || true
}

# Block all remote TCP access to the valkey port via iptables.
# Localhost is allowed so local health checks and replicaof still work.
# Prevents external clients from hitting valkey before role transition.
apply_replica_gate() {
	sudo iptables -I INPUT 1 -p tcp --dport "$VALKEY_PORT" ! -s 127.0.0.1 -j REJECT 2>/dev/null || true
}

# Remove the iptables gate — called on exit (trap) and after role is set.
remove_replica_gate() {
	sudo iptables -D INPUT -p tcp --dport "$VALKEY_PORT" ! -s 127.0.0.1 -j REJECT 2>/dev/null || true
}

# Safety net: always remove the gate on exit to avoid locking out valkey.
trap remove_replica_gate EXIT

echo "CRIU Restore - Replica Setup"
echo "  Listen IP  : $REPLICA_IP"
echo "  Port       : $CRIU_PORT"
echo "  Images Dir : $IMAGES_DIR"
echo "  Timeout    : ${WAIT_TIMEOUT}s"
echo "================================================================"
mark_phase_event "REPLICA_RESTORE_SCRIPT_START"

# --- Step 1: Clean slate ----------------------------------------------------
# Kill any leftover valkey so CRIU restore can recreate the process.
echo "Step 1: Killing valkey-server"
sudo pkill -9 valkey-server 2>/dev/null || true
echo "valkey-server killed"

# If the previous restored valkey had the same PID we want to restore (common
# when re-running without restarting the PRIMARY), we can hit EEXIST during
# pid-restore if the old process is still a zombie. Wait until it's fully
# gone from the process table.
for i in $(seq 1 200); do
	if ! pgrep -x valkey-server >/dev/null 2>&1; then
		break
	fi
	sleep 0.01
done

echo "Step 1a: Resetting valkey log files"
sudo truncate -s 0 /var/log/valkey/stderr.log 2>/dev/null || true
sudo truncate -s 0 /var/log/valkey/stdout.log 2>/dev/null || true

# --- Step 1b: Network gate ---------------------------------------------------
# Block remote clients immediately. The gate stays up until replicaof is
# configured and write protection is verified (Step 8d).
echo "Step 1b: Applying temporary replica network gate"
apply_replica_gate
mark_phase_event "REPLICA_GATE_APPLIED"

# --- Step 2: Signal readiness to PRIMARY -------------------------------------
# The primary's migrate.sh polls for this file on shared storage before
# starting the CRIU dump.
echo "Step 2: Creating ready signal"
echo "READY" | sudo tee "$IMAGES_DIR/ready.log" >/dev/null
echo "Ready signal created at $IMAGES_DIR/ready.log"
mark_phase_event "REPLICA_READY_SIGNAL_CREATED"

# --- Step 3: Wait for source page-server ------------------------------------
# The primary writes "PAGE SERVER READY TO SERVE" to lazy-primary.log after
# the dump completes and the page server is accepting connections. We poll
# the shared log file until the marker appears.
echo "Step 3: Waiting for source COW/page-server readiness..."
START_TIME=$(date +%s)
while true; do
	if [ -f "$LOG_FILE" ] && sudo grep -Eq "$PAGE_SERVER_READY_PATTERN" "$LOG_FILE" 2>/dev/null; then
		echo "Source ready marker observed"
		mark_phase_event "REPLICA_PAGE_SERVER_READY"
		break
	fi
	ELAPSED=$(($(date +%s) - START_TIME))
	if [ "$ELAPSED" -ge "$WAIT_TIMEOUT" ]; then
		echo "Timeout waiting for source COW/page-server readiness"
		exit 1
	fi
	sleep 0.5
done

# --- Step 4: Background replication setup ------------------------------------
# Start wait_and_replicate.sh which waits for valkey to respond, then
# runs REPLICAOF to configure this instance as a replica of the source.
# Runs in background so it doesn't block the restore.
echo "Step 4: Starting wait_and_replicate.sh in background"
"$SCRIPT_DIR/wait_and_replicate.sh" &
REPLICATE_PID=$!
echo "wait_and_replicate.sh started (PID: $REPLICATE_PID)"
mark_phase_event "REPLICA_REPLICATE_TASK_STARTED"

# --- Step 5/6: Lazy-pages + restore with retry ------------------------------
# Start the lazy-pages daemon (connects to source page server over TCP)
# and CRIU restore (connects to lazy-pages via local Unix socket).
#
# Retry loop handles transient "Unexpected EOF on (empty-image)" failures
# that occur when dump images aren't fully flushed to shared storage yet.
# Each retry restarts both lazy-pages and restore from scratch.
echo "Step 5: Starting lazy-pages + restore"
RESTORE_ARGS=(
	--images-dir "$IMAGES_DIR"
	--lazy-pages
	--tcp-close
	--cow-dump
	--skip-file-rwx-check
	--file-validation filesize   # Tolerate library build-ID mismatches
)
if [ "$FAST_CUTOVER" = "1" ]; then
	RESTORE_ARGS+=(--leave-stopped)  # Restore process in SIGSTOP state
fi

RESTORE_OK=0
for attempt in $(seq 1 "$RESTORE_RETRY_ATTEMPTS"); do
	echo "  Restore attempt $attempt/$RESTORE_RETRY_ATTEMPTS"
	sudo rm -f "$IMAGES_DIR/lazy-server.log" "$IMAGES_DIR/lazy-restore.log"

	# Start lazy-pages daemon: bridges page faults to source page server
	sudo "$CRIU_BIN" lazy-pages \
		--images-dir "$IMAGES_DIR" \
		--page-server \
		--address "$PRIMARY_IP" \
		--port "$CRIU_PORT" \
		--cow-dump \
		--tcp-close \
		-v1 -o "$IMAGES_DIR/lazy-server.log" &
	LAZY_PAGES_PID=$!
	mark_phase_event "REPLICA_LAZY_PAGES_STARTED"

	# Poll for the Unix socket instead of a fixed sleep.
	# The socket appears when lazy-pages calls listen(), typically in ~5-20ms.
	LAZY_SOCK="$IMAGES_DIR/lazy-pages.socket"
	for _i in $(seq 1 200); do
		[ -S "$LAZY_SOCK" ] && break
		sleep 0.005
	done

	# Check if lazy-pages died during startup (empty-image race)
	if ! kill -0 "$LAZY_PAGES_PID" 2>/dev/null; then
		if sudo grep -qi "Unexpected EOF on (empty-image)" "$IMAGES_DIR/lazy-server.log" 2>/dev/null; then
			sleep "$RESTORE_RETRY_INTERVAL_S"
			continue
		fi
		echo "ERROR: lazy-pages exited early"
		sudo tail -n 120 "$IMAGES_DIR/lazy-server.log" 2>/dev/null || true
		exit 1
	fi

	# Run CRIU restore: recreates the process from dump images.
	# In FAST_CUTOVER mode, the process is left in SIGSTOP state.
	if sudo "$CRIU_BIN" restore "${RESTORE_ARGS[@]}" -v1 -o "$IMAGES_DIR/lazy-restore.log"; then
		RESTORE_OK=1
		mark_phase_event "REPLICA_CRIU_RESTORE_STARTED"
		break
	fi

	# Retry on transient empty-image race in restore
	if sudo grep -qi "Unexpected EOF on (empty-image)" "$IMAGES_DIR/lazy-restore.log" 2>/dev/null ||
	   sudo grep -qi "Unexpected EOF on (empty-image)" "$IMAGES_DIR/lazy-server.log" 2>/dev/null; then
		sudo kill -9 "$LAZY_PAGES_PID" 2>/dev/null || true
		sleep "$RESTORE_RETRY_INTERVAL_S"
		continue
	fi

	# Non-transient failure — bail out
	echo "ERROR: restore failed"
	sudo tail -n 120 "$IMAGES_DIR/lazy-restore.log" 2>/dev/null || true
	sudo tail -n 120 "$IMAGES_DIR/lazy-server.log" 2>/dev/null || true
	exit 1
done

if [ "$RESTORE_OK" -ne 1 ]; then
	echo "ERROR: restore did not succeed after $RESTORE_RETRY_ATTEMPTS attempts"
	sudo tail -n 120 "$IMAGES_DIR/lazy-restore.log" 2>/dev/null || true
	sudo tail -n 120 "$IMAGES_DIR/lazy-server.log" 2>/dev/null || true
	exit 1
fi

# --- Step 7: Wait for restored process --------------------------------------
VALKEY_PID=""
if [ "$FAST_CUTOVER" = "1" ]; then
  # Fast cutover: process was restored in SIGSTOP state.
  # Wait for it to appear in the process table (it won't respond to PING yet —
  # the primary sends SIGCONT at cutover time).
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
  # Normal mode: process was restored and resumed immediately.
  # Wait for it to respond to PING (pages are demand-faulted as needed).
  echo "Step 7: Waiting for valkey to be responsive..."
  for i in $(seq 1 "$RESTORE_MAX_PING_ATTEMPTS"); do
    if valkey-cli ping &>/dev/null; then
      echo "Valkey is up"
      mark_phase_event "REPLICA_VALKEY_PING_READY"
      break
    fi
    sleep "$RESTORE_PING_INTERVAL_S"
  done
fi

# --- Step 8: Post-restore verification --------------------------------------
echo "Step 8: Verifying restore..."
if [ "$RESTORE_VERIFY_DELAY_S" != "0" ]; then
	sleep "$RESTORE_VERIFY_DELAY_S"
fi

# Step 8b: Wait for wait_and_replicate.sh to finish configuring REPLICAOF.
# This must complete before we open the network gate, otherwise external
# clients could see a standalone instance instead of a replica.
echo "Step 8b: Waiting for replica configuration task..."
if ! wait "$REPLICATE_PID"; then
	echo "ERROR: wait_and_replicate.sh failed"
	exit 1
fi
echo "Replica configuration completed"
mark_phase_event "REPLICA_REPLICATE_TASK_DONE"

# Step 8c: Verify the replica rejects writes with READONLY.
# This confirms REPLICAOF took effect before we open to external traffic.
echo "Step 8c: Verifying replica write protection"
WRITE_GUARD_OK=0
mark_phase_event "REPLICA_WRITE_GUARD_START"
for i in $(seq 1 "$RESTORE_WRITE_GUARD_ATTEMPTS"); do
  WRITE_RESP=$(valkey-cli -p "$VALKEY_PORT" set __criu_replica_probe__ 1 2>&1 || true)
  if printf "%s\n" "$WRITE_RESP" | grep -qi "READONLY"; then
    WRITE_GUARD_OK=1
    break
  fi
  sleep "$RESTORE_WRITE_GUARD_INTERVAL_S"
done
if [ "$WRITE_GUARD_OK" -ne 1 ]; then
  echo "ERROR: replica accepted write or did not return READONLY"
  valkey-cli -p "$VALKEY_PORT" del __criu_replica_probe__ >/dev/null 2>&1 || true
  exit 1
fi
mark_phase_event "REPLICA_WRITE_GUARD_OK"

# Step 8d: Remove the iptables gate — external clients can now connect.
echo "Step 8d: Removing temporary replica network gate"
remove_replica_gate
mark_phase_event "REPLICA_GATE_REMOVED"

# --- Summary -----------------------------------------------------------------
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
  mark_phase_event "REPLICA_RESTORE_SCRIPT_DONE"
else
  echo "ERROR: Valkey not responding after restore"
  exit 1
fi

exit 0
