#!/bin/bash
set -euo pipefail

# Wait for valkey to be responsive then configure as replica
# Run on REPLICA machine after CRIU restore

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

MAX_WAIT=600  # 600 × 0.1s = 60s

echo "Waiting for Valkey server to start responding to PING..."

for i in $(seq 1 $MAX_WAIT); do
  if valkey-cli ping &>/dev/null; then
    echo "Valkey is responsive!"
    echo "Configuring as replica of ${PRIMARY_IP}:${VALKEY_PORT}..."
    if valkey-cli replicaof "$PRIMARY_IP" "$VALKEY_PORT"; then
      echo "Successfully configured as replica of ${PRIMARY_IP}:${VALKEY_PORT}"
      exit 0
    else
      echo "Failed to configure replica. Check connection or authentication."
      exit 1
    fi
  fi
  sleep 0.1
done

echo "Timeout: Valkey did not become responsive within ${MAX_WAIT}×0.1s seconds."
exit 1
