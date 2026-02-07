#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

DATA_SIZE_GB=${1:-$DEFAULT_DATA_SIZE_GB}

HARNESS_SOURCE_HOST=${HARNESS_SOURCE_HOST:-127.0.0.1}
HARNESS_SOURCE_PORT=${HARNESS_SOURCE_PORT:-$VALKEY_PORT}
HARNESS_REPLICA_HOST=${HARNESS_REPLICA_HOST:-$REPLICA_IP}
HARNESS_REPLICA_PORT=${HARNESS_REPLICA_PORT:-$VALKEY_PORT}
HARNESS_KEYSPACE=${HARNESS_KEYSPACE:-100000}
HARNESS_SAMPLE_SIZE=${HARNESS_SAMPLE_SIZE:-5000}
HARNESS_EXPECTED_CHECK_LIMIT=${HARNESS_EXPECTED_CHECK_LIMIT:-5000}
HARNESS_SOURCE_WRITERS=${HARNESS_SOURCE_WRITERS:-4}
HARNESS_SOURCE_READERS=${HARNESS_SOURCE_READERS:-8}
HARNESS_REPLICA_READERS=${HARNESS_REPLICA_READERS:-8}
HARNESS_REPLICA_WRITERS=${HARNESS_REPLICA_WRITERS:-2}
HARNESS_STATUS_INTERVAL=${HARNESS_STATUS_INTERVAL:-2}
HARNESS_CATCHUP_TIMEOUT=${HARNESS_CATCHUP_TIMEOUT:-120}
HARNESS_CHECK_TIMEOUT=${HARNESS_CHECK_TIMEOUT:-45}
HARNESS_CUTOVER_SOURCE_WRITE_MAX_OUTAGE_MS=${HARNESS_CUTOVER_SOURCE_WRITE_MAX_OUTAGE_MS:-250}
HARNESS_CUTOVER_SOURCE_READ_MAX_OUTAGE_MS=${HARNESS_CUTOVER_SOURCE_READ_MAX_OUTAGE_MS:-250}
HARNESS_CUTOVER_REPLICA_READ_MAX_OUTAGE_MS=${HARNESS_CUTOVER_REPLICA_READ_MAX_OUTAGE_MS:-250}
HARNESS_WARMUP_SECONDS=${HARNESS_WARMUP_SECONDS:-2}
HARNESS_SETTLE_SECONDS=${HARNESS_SETTLE_SECONDS:-10}
HARNESS_REPORT=${HARNESS_REPORT:-/tmp/valkey_traffic_harness_report.json}
HARNESS_LOG=${HARNESS_LOG:-/tmp/valkey_traffic_harness.log}
HARNESS_CUTOVER_MARKER=${HARNESS_CUTOVER_MARKER:-$IMAGES_DIR/valkey_cutover_marker.log}
SCENARIO_KPI_REPORT=${SCENARIO_KPI_REPORT:-/tmp/criu_kpi_report.json}
SCENARIO_PREFILL=${SCENARIO_PREFILL:-1}
SCENARIO_KILL_DUMP_AFTER=${SCENARIO_KILL_DUMP_AFTER:-1}
SCENARIO_RESTART_SOURCE_BEFORE_PREFILL=${SCENARIO_RESTART_SOURCE_BEFORE_PREFILL:-1}

log() { echo "[$(date '+%H:%M:%S')] $*"; }

cleanup_dump() {
	if [ "$SCENARIO_KILL_DUMP_AFTER" = "1" ]; then
		DUMP_PIDS=$(sudo pgrep -f "criu dump --tree" 2>/dev/null || true)
		if [ -n "$DUMP_PIDS" ]; then
			sudo kill -9 $DUMP_PIDS 2>/dev/null || true
		fi
	fi
}

restart_source_valkey() {
	log "Restarting source valkey process for clean state"
	sudo pkill -9 valkey-server 2>/dev/null || true

	for _ in $(seq 1 60); do
		if timeout 2s valkey-cli -h "$HARNESS_SOURCE_HOST" -p "$HARNESS_SOURCE_PORT" ping >/dev/null 2>&1; then
			log "Source valkey is responsive"
			return 0
		fi
		sleep 0.5
	done

	log "ERROR: source valkey did not become responsive"
	return 1
}

ensure_source_valkey_ready() {
	if timeout 2s valkey-cli -h "$HARNESS_SOURCE_HOST" -p "$HARNESS_SOURCE_PORT" ping >/dev/null 2>&1; then
		return 0
	fi
	return restart_source_valkey
}

HARNESS_PID=""
cleanup() {
	if [ -n "$HARNESS_PID" ] && kill -0 "$HARNESS_PID" 2>/dev/null; then
		kill -INT "$HARNESS_PID" 2>/dev/null || true
		wait "$HARNESS_PID" 2>/dev/null || true
	fi
	cleanup_dump
}
trap cleanup EXIT

if [ "$SCENARIO_RESTART_SOURCE_BEFORE_PREFILL" = "1" ]; then
	restart_source_valkey
else
	ensure_source_valkey_ready
fi

if [ "$SCENARIO_PREFILL" = "1" ]; then
	log "Prefill source dataset (~${DATA_SIZE_GB}GB) before traffic starts"
	NUM_KEYS=$((DATA_SIZE_GB * 25300))
	NUM_OPS=$((NUM_KEYS + 50000))
	timeout 300s valkey-benchmark -h "$HARNESS_SOURCE_HOST" -p "$HARNESS_SOURCE_PORT" \
		-t set -d 64000 -r "$NUM_KEYS" -n "$NUM_OPS" --threads 10 -q
fi

log "Starting real traffic harness (report: $HARNESS_REPORT)"
sudo rm -f "$HARNESS_CUTOVER_MARKER" 2>/dev/null || true
if ! sudo install -m 666 /dev/null "$HARNESS_CUTOVER_MARKER" 2>/dev/null; then
	touch "$HARNESS_CUTOVER_MARKER" 2>/dev/null || true
	chmod 666 "$HARNESS_CUTOVER_MARKER" 2>/dev/null || true
fi
python3 "$SCRIPT_DIR/valkey_traffic_harness.py" \
	--source-host "$HARNESS_SOURCE_HOST" \
	--source-port "$HARNESS_SOURCE_PORT" \
	--replica-host "$HARNESS_REPLICA_HOST" \
	--replica-port "$HARNESS_REPLICA_PORT" \
	--keyspace "$HARNESS_KEYSPACE" \
	--sample-size "$HARNESS_SAMPLE_SIZE" \
	--expected-check-limit "$HARNESS_EXPECTED_CHECK_LIMIT" \
	--source-writers "$HARNESS_SOURCE_WRITERS" \
	--source-readers "$HARNESS_SOURCE_READERS" \
	--replica-readers "$HARNESS_REPLICA_READERS" \
	--replica-writers "$HARNESS_REPLICA_WRITERS" \
	--status-interval "$HARNESS_STATUS_INTERVAL" \
	--catchup-timeout "$HARNESS_CATCHUP_TIMEOUT" \
	--check-timeout "$HARNESS_CHECK_TIMEOUT" \
	--cutover-marker-file "$HARNESS_CUTOVER_MARKER" \
	--cutover-source-write-max-outage-ms "$HARNESS_CUTOVER_SOURCE_WRITE_MAX_OUTAGE_MS" \
	--cutover-source-read-max-outage-ms "$HARNESS_CUTOVER_SOURCE_READ_MAX_OUTAGE_MS" \
	--cutover-replica-read-max-outage-ms "$HARNESS_CUTOVER_REPLICA_READ_MAX_OUTAGE_MS" \
	--report "$HARNESS_REPORT" >"$HARNESS_LOG" 2>&1 &
HARNESS_PID=$!
log "Harness PID: $HARNESS_PID"

sleep "$HARNESS_WARMUP_SECONDS"

log "Running migration with ${DATA_SIZE_GB}GB dataset"
RUN_WORKLOAD_DURING_MIGRATION=0 KEEP_SOURCE_RUNNING=1 SKIP_FILL=1 STOP_DUMP_ON_COMPLETE=0 CUTOVER_MARKER_FILE="$HARNESS_CUTOVER_MARKER" \
	"$SCRIPT_DIR/migrate.sh" "$DATA_SIZE_GB"

sleep "$HARNESS_SETTLE_SECONDS"

log "Stopping harness"
kill -INT "$HARNESS_PID" 2>/dev/null || true
HARNESS_RC=0
wait "$HARNESS_PID" || HARNESS_RC=$?
HARNESS_PID=""

log "Harness log tail:"
tail -n 20 "$HARNESS_LOG" || true

if [ -f "$HARNESS_REPORT" ]; then
	log "Harness summary:"
	python3 - <<'PY' "$HARNESS_REPORT"
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    report = json.load(fh)

metrics = report.get("metrics", {})
sw = metrics.get("source_write", {})
sr = metrics.get("source_read", {})
rr = metrics.get("replica_read", {})
cut = report.get("cutover", {})
gates = report.get("gates", {})
phases = report.get("phases", {})
print(f"pass={report.get('pass')}")
print(f"replica_write_accepted={report.get('replica_write_accepted')}")
print(f"replication_caught_up={report.get('replication_caught_up')}")
print(f"sample_mismatches={report.get('data_checks', {}).get('sample_value_mismatches')}")
print(f"source_expected_mismatches={report.get('data_checks', {}).get('source_expected_mismatches')}")
print(f"replica_expected_mismatches={report.get('data_checks', {}).get('replica_expected_mismatches')}")
print(f"touched_key_mismatches={report.get('data_checks', {}).get('touched_key_mismatches')}")
print(f"source_write_p99_ms={sw.get('latency_ms_p99', 0):.3f}")
print(f"source_read_p99_ms={sr.get('latency_ms_p99', 0):.3f}")
print(f"replica_read_p99_ms={rr.get('latency_ms_p99', 0):.3f}")
print(f"source_write_max_outage_ms={sw.get('max_outage_ms', 0):.3f}")
print(f"source_read_max_outage_ms={sr.get('max_outage_ms', 0):.3f}")
print(f"replica_read_max_outage_ms={rr.get('max_outage_ms', 0):.3f}")
print(f"cutover_window_found={cut.get('window_found', False)}")
print(f"cutover_gate_ok={gates.get('cutover_gate_ok', False)}")
print(f"cutover_window_ms={cut.get('window_ms', 0):.3f}")
print(f"cutover_source_write_max_outage_ms={cut.get('source_write_max_outage_ms', 0):.3f}")
print(f"cutover_source_read_max_outage_ms={cut.get('source_read_max_outage_ms', 0):.3f}")
print(f"cutover_replica_read_max_outage_ms={cut.get('replica_read_max_outage_ms', 0):.3f}")
print(f"phase_events_found={phases.get('events_found', False)}")
print(f"phase_replica_events_found={phases.get('replica_events_found', False)}")
print(f"phase_wait_ping_ms={phases.get('wait_ping_ms', 0) or 0:.3f}")
print(f"phase_replicaof_rpc_ms={phases.get('replicaof_rpc_ms', 0) or 0:.3f}")
print(f"phase_role_wait_ms={phases.get('role_wait_ms', 0) or 0:.3f}")
print(f"phase_write_guard_ms={phases.get('write_guard_ms', 0) or 0:.3f}")
print(f"phase_replicaof_done_to_gate_removed_ms={phases.get('replicaof_done_to_gate_removed_ms', 0) or 0:.3f}")
print(f"phase_post_role_to_gate_removed_ms={phases.get('post_role_to_gate_removed_ms', 0) or 0:.3f}")
print(f"phase_cutover_to_write_guard_ok_ms={phases.get('cutover_to_write_guard_ok_ms', 0) or 0:.3f}")
print(f"phase_cutover_to_gate_removed_ms={phases.get('cutover_to_gate_removed_ms', 0) or 0:.3f}")
PY
	python3 "$SCRIPT_DIR/criu_kpi_report.py" \
		--harness-report "$HARNESS_REPORT" \
		--primary-log "$IMAGES_DIR/lazy-primary.log" \
		--output "$SCENARIO_KPI_REPORT"
fi

if [ "$HARNESS_RC" -ne 0 ]; then
	log "ERROR: traffic harness failed (rc=$HARNESS_RC)"
	exit "$HARNESS_RC"
fi

log "Scenario run completed successfully"
