#!/bin/bash
set -euo pipefail

# Wait for valkey to be responsive then configure as replica
# Run on REPLICA machine after CRIU restore

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

MAX_WAIT_PING=${MAX_WAIT_PING:-600}      # 600 × 0.1s = 60s
MAX_WAIT_REPLICA=${MAX_WAIT_REPLICA:-1200}  # 1200 × 0.1s = 120s
WAIT_REPLICA_ROLE_ACTIVE=${WAIT_REPLICA_ROLE_ACTIVE:-1}
WAIT_REPLICA_LINK_UP=${WAIT_REPLICA_LINK_UP:-0}
CUTOVER_MARKER_FILE=${CUTOVER_MARKER_FILE:-}
REPLICA_POLL_INTERVAL_S=${REPLICA_POLL_INTERVAL_S:-0.02}

mark_phase_event() {
  local event="$1"
  local ts_ms

  if [ -z "$CUTOVER_MARKER_FILE" ]; then
    return 0
  fi

  ts_ms=$(date +%s%3N)
  mkdir -p "$(dirname "$CUTOVER_MARKER_FILE")" 2>/dev/null || true
  printf "%s %s %s\n" "$event" "$ts_ms" "REPLICA_REPLICAOF" >>"$CUTOVER_MARKER_FILE" 2>/dev/null || true
}

echo "Waiting for Valkey server to start responding to PING..."
mark_phase_event "REPLICA_WAIT_PING_START"

for i in $(seq 1 "$MAX_WAIT_PING"); do
  if valkey-cli ping &>/dev/null; then
    echo "Valkey is responsive!"
    mark_phase_event "REPLICA_WAIT_PING_READY"
    break
  fi
  sleep "$REPLICA_POLL_INTERVAL_S"
done

if ! valkey-cli ping &>/dev/null; then
  echo "Timeout: Valkey did not become responsive within ${MAX_WAIT_PING}×0.1s seconds."
  exit 1
fi

echo "Configuring as replica of ${PRIMARY_IP}:${VALKEY_PORT}..."
mark_phase_event "REPLICA_REPLICAOF_START"
REPLICA_SET=0
for i in $(seq 1 "$MAX_WAIT_REPLICA"); do
  if valkey-cli replicaof "$PRIMARY_IP" "$VALKEY_PORT" >/dev/null 2>&1; then
    REPLICA_SET=1
    mark_phase_event "REPLICA_REPLICAOF_SET"
    break
  fi
  sleep "$REPLICA_POLL_INTERVAL_S"
done

if [ "$REPLICA_SET" -ne 1 ]; then
  echo "Failed to configure replicaof within ${MAX_WAIT_REPLICA}×0.1s seconds."
  exit 1
fi

if [ "$WAIT_REPLICA_ROLE_ACTIVE" != "1" ] && [ "$WAIT_REPLICA_LINK_UP" != "1" ]; then
  echo "Replica command accepted; skipping role/link waits"
  mark_phase_event "REPLICA_REPLICAOF_DONE"
  exit 0
fi

# Wait until role transition is visible. This is enough to enforce READONLY.
echo "Waiting for replica role to be active..."
mark_phase_event "REPLICA_ROLE_WAIT_START"
for i in $(seq 1 "$MAX_WAIT_REPLICA"); do
  INFO=$(valkey-cli info replication 2>/dev/null || true)
  ROLE=$(printf "%s\n" "$INFO" | awk -F: '/^role:/ {gsub(/\r/, "", $2); print $2}')

  if [ "$ROLE" = "replica" ] || [ "$ROLE" = "slave" ]; then
    echo "Replica role is active"
    mark_phase_event "REPLICA_ROLE_ACTIVE"
    break
  fi
  sleep "$REPLICA_POLL_INTERVAL_S"
done

if ! INFO=$(valkey-cli info replication 2>/dev/null || true); then
  INFO=""
fi
ROLE=$(printf "%s\n" "$INFO" | awk -F: '/^role:/ {gsub(/\r/, "", $2); print $2}')
if ! { [ "$ROLE" = "replica" ] || [ "$ROLE" = "slave" ]; }; then
  echo "Timeout waiting for replica role to become active."
  exit 1
fi

if [ "$WAIT_REPLICA_LINK_UP" != "1" ]; then
  echo "Replica configured (role active); skipping master_link_status wait"
  mark_phase_event "REPLICA_REPLICAOF_DONE"
  exit 0
fi

echo "Waiting for replica link to become active..."
mark_phase_event "REPLICA_LINK_WAIT_START"
for i in $(seq 1 "$MAX_WAIT_REPLICA"); do
  INFO=$(valkey-cli info replication 2>/dev/null || true)
  ROLE=$(printf "%s\n" "$INFO" | awk -F: '/^role:/ {gsub(/\r/, "", $2); print $2}')
  LINK=$(printf "%s\n" "$INFO" | awk -F: '/^master_link_status:/ {gsub(/\r/, "", $2); print $2}')

  if { [ "$ROLE" = "replica" ] || [ "$ROLE" = "slave" ]; } && [ "$LINK" = "up" ]; then
    echo "Successfully configured as replica of ${PRIMARY_IP}:${VALKEY_PORT} (link up)"
    mark_phase_event "REPLICA_LINK_UP"
    mark_phase_event "REPLICA_REPLICAOF_DONE"
    exit 0
  fi
  sleep "$REPLICA_POLL_INTERVAL_S"
done

echo "Timeout waiting for replica role/link to become active."
exit 1
