#!/bin/bash
set -euo pipefail

REPLICA_HOST="172.31.15.117"  # Master internal IP
REPLICA_PORT=6379
MAX_WAIT=30000  # 3000 × 0.1s = 300s (5 minutes)

echo "⏳ Waiting for Valkey server to start responding to PING..."

for i in $(seq 1 $MAX_WAIT); do
  if valkey-cli ping &>/dev/null; then
    echo "💡 Valkey is responsive!"
    echo "🔁 Configuring as replica of ${REPLICA_HOST}:${REPLICA_PORT}..."
    if valkey-cli replicaof "$REPLICA_HOST" "$REPLICA_PORT"; then
      echo "✅ Successfully configured as replica of ${REPLICA_HOST}:${REPLICA_PORT}"
      exit 0
    else
      echo "⚠️ Failed to configure replica. Check connection or authentication."
      exit 1
    fi
  fi
  sleep 0.1
done

echo "❌ Timeout: Valkey did not become responsive within ${MAX_WAIT}×0.1s seconds."
exit 1
