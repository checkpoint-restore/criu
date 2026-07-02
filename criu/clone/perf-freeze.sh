#!/bin/bash
#
# perf-freeze.sh - Profile CRIU CLONE dump during the Phase 3 freeze window only.
#
# Usage:
#   Shell A:  sudo ./perf-freeze.sh              # default: system-wide + END regex
#   Shell A:  sudo ./perf-freeze.sh -d 10        # fixed 10s recording after START
#   Shell A:  sudo ./perf-freeze.sh -P           # per-pid mode (criu PIDs only)
#   Shell B:  run your criu dump.
#
# At START the script:
#   - resolves criu PIDs via pgrep and aborts if none are running
#   - logs the PIDs so you can confirm perf is targeting the right run
#   - records system-wide (-a) by default, or per-pid (-p) with -P
# After stop it prints a per-process sample summary so you can verify
# criu actually appears in the capture.
#

set -u

PERF=/usr/lib/linux-tools/6.17.0-1012-aws/perf
LOG=/fsx/lazy/lazy-primary.log
OUT=/tmp/criu-freeze.data
PIDFILE=/tmp/criu-freeze-perf.pid
CRIU_PROCNAME=criu

# Start matches freeze entry. End matches freeze exit.
# VERIFY against your log first - see PREFLIGHT below.
START_RE='Phase 3 freeze started|clone_wait_p3_threads starting|TIMING: clone_wait_p3_threads|freeze signal|Freezing process'
END_RE='TIMING: clone_wait_p3_threads took'

# Safety cap: stop perf after this many seconds even if END_RE never matches.
# Freeze window is ~3s; 30s is a generous cap.
MAX_SECONDS=30
# Allow -d SEC to override (fixed duration, ignore END_RE)
FIXED_DURATION=0
# -P switches from system-wide (-a) to per-pid (-p CRIU_PIDS)
PER_PID_MODE=0
while getopts "d:Ph" opt; do
	case "$opt" in
	d) FIXED_DURATION=$OPTARG ;;
	P) PER_PID_MODE=1 ;;
	h)
		sed -n '2,18p' "$0"
		exit 0
		;;
	esac
done

if [ "$(id -u)" -ne 0 ]; then
	echo "perf-freeze: must run as root (sudo $0)" >&2
	exit 1
fi
if [ ! -x "$PERF" ]; then
	echo "perf-freeze: $PERF not executable" >&2
	exit 1
fi
if [ ! -r "$LOG" ]; then
	echo "perf-freeze: cannot read $LOG" >&2
	exit 1
fi

STAT_OUT=/tmp/criu-freeze-stat.txt
rm -f "$OUT" "$PIDFILE" "$STAT_OUT"

PERF_PID=0
STAT_PID=0
TAIL_PID=0

cleanup() {
	if [ -f "$PIDFILE" ]; then
		local pid
		pid=$(cat "$PIDFILE" 2>/dev/null || true)
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			echo "perf-freeze: cleanup - stopping perf (pid $pid)" >&2
			kill -INT "$pid" 2>/dev/null
			# Give perf up to 5s to flush
			for _ in 1 2 3 4 5; do
				kill -0 "$pid" 2>/dev/null || break
				sleep 1
			done
			kill -KILL "$pid" 2>/dev/null || true
		fi
		rm -f "$PIDFILE"
	fi
	if [ "$STAT_PID" -gt 0 ] && kill -0 "$STAT_PID" 2>/dev/null; then
		kill -INT "$STAT_PID" 2>/dev/null || true
	fi
	if [ "$TAIL_PID" -gt 0 ] && kill -0 "$TAIL_PID" 2>/dev/null; then
		kill "$TAIL_PID" 2>/dev/null || true
	fi
}
trap cleanup EXIT INT TERM

# ---- PREFLIGHT: show candidate markers from recent log ----
echo "perf-freeze: preflight - recent freeze-related lines in log:" >&2
grep -nE 'freeze|clone_wait_p3|Phase 3|P3 (complete|done)|Dump finished' "$LOG" 2>/dev/null | tail -10 >&2 || true
echo "---" >&2
echo "perf-freeze: START regex: $START_RE" >&2
echo "perf-freeze: END   regex: $END_RE" >&2
echo "perf-freeze: MAX_SECONDS (safety stop): $MAX_SECONDS" >&2
[ "$FIXED_DURATION" -gt 0 ] && echo "perf-freeze: FIXED_DURATION override: ${FIXED_DURATION}s" >&2
echo "perf-freeze: waiting for START..." >&2

resolve_criu_pids() {
	# Comma-separated list of criu PIDs, or empty string if none.
	pgrep -d, -x "$CRIU_PROCNAME" 2>/dev/null || true
}

start_perf() {
	local pids
	pids=$(resolve_criu_pids)

	if [ -z "$pids" ]; then
		echo "perf-freeze: ERROR - no '$CRIU_PROCNAME' process found at START" >&2
		echo "perf-freeze: (pgrep -x $CRIU_PROCNAME returned empty). Aborting record." >&2
		return 1
	fi

	echo "perf-freeze: criu PIDs at START: $pids" >&2
	echo "perf-freeze: criu processes:" >&2
	ps -o pid,ppid,cmd -p "$(echo "$pids" | tr , ' ')" >&2 || true

	if [ "$PER_PID_MODE" -eq 1 ]; then
		echo "perf-freeze: mode: per-pid (-p $pids)" >&2
		"$PERF" record -F 999 -g -p "$pids" -o "$OUT" >/tmp/perf-freeze.stderr 2>&1 &
	else
		echo "perf-freeze: mode: system-wide (-a); will verify criu PIDs appear in capture at stop" >&2
		"$PERF" record -F 999 -g -a -o "$OUT" >/tmp/perf-freeze.stderr 2>&1 &
	fi
	PERF_PID=$!
	echo "$PERF_PID" > "$PIDFILE"
	echo "$pids" > /tmp/perf-freeze.criu_pids
	echo "perf-freeze: perf record started (pid $PERF_PID)" >&2

	# Also run perf stat for hardware counters (IPC, cache misses)
	"$PERF" stat -e cycles,instructions,cache-references,cache-misses,LLC-loads,LLC-load-misses,L1-dcache-loads,L1-dcache-load-misses -p "$pids" -o "$STAT_OUT" 2>/dev/null &
	STAT_PID=$!
	echo "perf-freeze: perf stat started (pid $STAT_PID)" >&2
}

verify_criu_in_capture() {
	# Post-capture sanity: list the top PIDs present in the perf.data and
	# check that at least one of the criu PIDs we recorded is among them.
	local expected=""
	[ -r /tmp/perf-freeze.criu_pids ] && expected=$(cat /tmp/perf-freeze.criu_pids)

	echo "perf-freeze: --- top processes in capture ---" >&2
	# perf report -s comm,pid: samples grouped by (process, pid)
	"$PERF" report -i "$OUT" --stdio -s comm,pid --no-children 2>/dev/null | \
		awk '/^[[:space:]]*[0-9]/{print} /^#/{next}' | head -15 >&2 || true
	echo "perf-freeze: -----------------------------------" >&2

	if [ -n "$expected" ]; then
		local found=0 pid
		for pid in $(echo "$expected" | tr , ' '); do
			if "$PERF" script -i "$OUT" --pid="$pid" 2>/dev/null | head -1 | grep -q .; then
				echo "perf-freeze: VERIFIED criu pid $pid has samples in capture" >&2
				found=1
				break
			fi
		done
		if [ "$found" -eq 0 ]; then
			echo "perf-freeze: WARNING - none of the recorded criu PIDs ($expected) appear in the capture" >&2
			echo "perf-freeze:   (criu may have exited before/during record, or was idle the whole window)" >&2
		fi
	fi
}

stop_perf() {
	if [ "$PERF_PID" -gt 0 ] && kill -0 "$PERF_PID" 2>/dev/null; then
		kill -INT "$PERF_PID" 2>/dev/null
		wait "$PERF_PID" 2>/dev/null
	fi
	if [ "$STAT_PID" -gt 0 ] && kill -0 "$STAT_PID" 2>/dev/null; then
		kill -INT "$STAT_PID" 2>/dev/null
		wait "$STAT_PID" 2>/dev/null
	fi
	rm -f "$PIDFILE"
	echo "perf-freeze: stopped. Output: $OUT" >&2
	if [ -s "$OUT" ]; then
		verify_criu_in_capture
	fi
	if [ -s "$STAT_OUT" ]; then
		echo "perf-freeze: --- hardware counters ---" >&2
		cat "$STAT_OUT" >&2
		echo "perf-freeze: ---" >&2
	fi
	echo "perf-freeze: inspect ->" >&2
	echo "  sudo $PERF report -i $OUT -g graph,0.5,caller --stdio | head -100" >&2
	echo "  sudo $PERF script -i $OUT | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > /tmp/freeze.svg" >&2
}

# ---- MAIN LOOP using process substitution ----
# Process substitution keeps break/exit in the main shell (not a subshell),
# so cleanup runs reliably and tail is a tracked child we can kill.
exec 3< <(exec tail -n0 -F "$LOG")
TAIL_PID=$!

START_EPOCH=0
while :; do
	# If perf is running, enforce MAX_SECONDS cap
	if [ "$PERF_PID" -gt 0 ]; then
		now=$(date +%s)
		elapsed=$((now - START_EPOCH))
		if [ "$FIXED_DURATION" -gt 0 ] && [ "$elapsed" -ge "$FIXED_DURATION" ]; then
			echo "perf-freeze: fixed ${FIXED_DURATION}s duration reached" >&2
			stop_perf
			break
		fi
		if [ "$elapsed" -ge "$MAX_SECONDS" ]; then
			echo "perf-freeze: MAX_SECONDS ($MAX_SECONDS) reached without END match - stopping anyway" >&2
			stop_perf
			break
		fi
	fi

	# Read with 1s timeout so we can re-check MAX_SECONDS
	if ! IFS= read -r -t 1 -u 3 line; then
		continue
	fi

	if [ "$PERF_PID" -eq 0 ]; then
		if echo "$line" | grep -qE "$START_RE"; then
			echo "perf-freeze: START matched: $line" >&2
			START_EPOCH=$(date +%s)
			if ! start_perf; then
				echo "perf-freeze: start_perf failed - aborting" >&2
				exit 2
			fi
		fi
	else
		# If -d was given, ignore END_RE; stop only on duration.
		if [ "$FIXED_DURATION" -eq 0 ] && echo "$line" | grep -qE "$END_RE"; then
			echo "perf-freeze: END matched: $line" >&2
			stop_perf
			break
		fi
	fi
done

exec 3<&-
