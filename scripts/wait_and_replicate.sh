#!/bin/bash
set -euo pipefail

# Wait for valkey to be responsive then configure as replica
# Run on REPLICA machine after CRIU restore

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

MAX_WAIT_PING=${MAX_WAIT_PING:-600}      # 600 × 0.1s = 60s
MAX_WAIT_REPLICA=${MAX_WAIT_REPLICA:-1200}  # 1200 × 0.1s = 120s
WAIT_REPLICA_LINK_UP=${WAIT_REPLICA_LINK_UP:-0}

echo "Waiting for Valkey server to start responding to PING..."

for i in $(seq 1 "$MAX_WAIT_PING"); do
  if valkey-cli ping &>/dev/null; then
    echo "Valkey is responsive!"
    break
  fi
  sleep 0.1
done

if ! valkey-cli ping &>/dev/null; then
  echo "Timeout: Valkey did not become responsive within ${MAX_WAIT_PING}×0.1s seconds."
  exit 1
fi

echo "Configuring as replica of ${PRIMARY_IP}:${VALKEY_PORT}..."
REPLICA_SET=0
for i in $(seq 1 "$MAX_WAIT_REPLICA"); do
  if valkey-cli replicaof "$PRIMARY_IP" "$VALKEY_PORT" >/dev/null 2>&1; then
    REPLICA_SET=1
    break
  fi
  sleep 0.1
done

if [ "$REPLICA_SET" -ne 1 ]; then
  echo "Failed to configure replicaof within ${MAX_WAIT_REPLICA}×0.1s seconds."
  exit 1
fi

# Wait until role transition is visible. This is enough to enforce READONLY.
echo "Waiting for replica role to be active..."
for i in $(seq 1 "$MAX_WAIT_REPLICA"); do
  INFO=$(valkey-cli info replication 2>/dev/null || true)
  ROLE=$(printf "%s\n" "$INFO" | awk -F: '/^role:/ {gsub(/\r/, "", $2); print $2}')

  if [ "$ROLE" = "replica" ] || [ "$ROLE" = "slave" ]; then
    echo "Replica role is active"
    break
  fi
  sleep 0.1
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
  exit 0
fi

echo "Waiting for replica link to become active..."
for i in $(seq 1 "$MAX_WAIT_REPLICA"); do
  INFO=$(valkey-cli info replication 2>/dev/null || true)
  ROLE=$(printf "%s\n" "$INFO" | awk -F: '/^role:/ {gsub(/\r/, "", $2); print $2}')
  LINK=$(printf "%s\n" "$INFO" | awk -F: '/^master_link_status:/ {gsub(/\r/, "", $2); print $2}')

  if { [ "$ROLE" = "replica" ] || [ "$ROLE" = "slave" ]; } && [ "$LINK" = "up" ]; then
    echo "Successfully configured as replica of ${PRIMARY_IP}:${VALKEY_PORT} (link up)"
    exit 0
  fi
  sleep 0.1
done

echo "Timeout waiting for replica role/link to become active."
exit 1
