#!/bin/bash
#
# perf-drain.sh - Profile CRIU CLONE dump during the drain phase.
#
# Usage:
#   Shell A:  sudo ./perf-drain.sh              # default: system-wide + END regex
#   Shell A:  sudo ./perf-drain.sh -d 30        # fixed 30s recording after START
#   Shell A:  sudo ./perf-drain.sh -P           # per-pid mode (criu PIDs only)
#   Shell B:  run your criu dump.
#
# At START the script:
#   - resolves criu PIDs via pgrep and aborts if none are running
#   - logs the PIDs so you can confirm perf is targeting the right run
#   - records system-wide (-a) by default, or per-pid (-p) with -P
# After stop it prints a per-process sample summary so you can verify
# criu actually appears in the capture.
#
# Thread balance analysis:
#   The script also monitors drain thread progress from the log and reports
#   a summary of how balanced the threads were (drained count per thread).
#

set -u

PERF=/usr/lib/linux-tools/6.17.0-1012-aws/perf
LOG=/fsx/lazy/lazy-server.log
OUT=/tmp/criu-drain.data
PIDFILE=/tmp/criu-drain-perf.pid
CRIU_PROCNAME=criu

# Start matches first drain thread start. End matches drain timing log.
START_RE='clone-uffd: Drain thread'
END_RE='TIMING: drain took'

# Safety cap: stop perf after this many seconds even if END_RE never matches.
# Drain can take 20-30s based on logs; 120s is a generous cap.
MAX_SECONDS=120
# Allow -d SEC to override (fixed duration, ignore END_RE)
FIXED_DURATION=0
# -P switches from system-wide (-a) to per-pid (-p CRIU_PIDS)
PER_PID_MODE=0
while getopts "d:Ph" opt; do
	case "$opt" in
	d) FIXED_DURATION=$OPTARG ;;
	P) PER_PID_MODE=1 ;;
	h)
		sed -n '2,22p' "$0"
		exit 0
		;;
	esac
done

if [ "$(id -u)" -ne 0 ]; then
	echo "perf-drain: must run as root (sudo $0)" >&2
	exit 1
fi
if [ ! -x "$PERF" ]; then
	echo "perf-drain: $PERF not executable" >&2
	exit 1
fi
if [ ! -r "$LOG" ]; then
	echo "perf-drain: cannot read $LOG" >&2
	exit 1
fi

STAT_OUT=/tmp/criu-drain-stat.txt
THREAD_BALANCE=/tmp/criu-drain-threads.txt
rm -f "$OUT" "$PIDFILE" "$STAT_OUT" "$THREAD_BALANCE"

PERF_PID=0
STAT_PID=0
TAIL_PID=0

cleanup() {
	if [ -f "$PIDFILE" ]; then
		local pid
		pid=$(cat "$PIDFILE" 2>/dev/null || true)
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			echo "perf-drain: cleanup - stopping perf (pid $pid)" >&2
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
echo "perf-drain: preflight - recent drain-related lines in log:" >&2
grep -nE 'Drain thread|TIMING: drain|drain took' "$LOG" 2>/dev/null | tail -10 >&2 || true
echo "---" >&2
echo "perf-drain: START regex: $START_RE" >&2
echo "perf-drain: END   regex: $END_RE" >&2
echo "perf-drain: MAX_SECONDS (safety stop): $MAX_SECONDS" >&2
[ "$FIXED_DURATION" -gt 0 ] && echo "perf-drain: FIXED_DURATION override: ${FIXED_DURATION}s" >&2
echo "perf-drain: waiting for START..." >&2

resolve_criu_pids() {
	# Comma-separated list of criu PIDs, or empty string if none.
	pgrep -d, -x "$CRIU_PROCNAME" 2>/dev/null || true
}

start_perf() {
	local pids
	pids=$(resolve_criu_pids)

	if [ -z "$pids" ]; then
		echo "perf-drain: ERROR - no '$CRIU_PROCNAME' process found at START" >&2
		echo "perf-drain: (pgrep -x $CRIU_PROCNAME returned empty). Aborting record." >&2
		return 1
	fi

	echo "perf-drain: criu PIDs at START: $pids" >&2
	echo "perf-drain: criu processes:" >&2
	ps -o pid,ppid,cmd -p "$(echo "$pids" | tr , ' ')" >&2 || true

	if [ "$PER_PID_MODE" -eq 1 ]; then
		echo "perf-drain: mode: per-pid (-p $pids)" >&2
		"$PERF" record -F 999 -g -p "$pids" -o "$OUT" >/tmp/perf-drain.stderr 2>&1 &
	else
		echo "perf-drain: mode: system-wide (-a); will verify criu PIDs appear in capture at stop" >&2
		"$PERF" record -F 999 -g -a -o "$OUT" >/tmp/perf-drain.stderr 2>&1 &
	fi
	PERF_PID=$!
	echo "$PERF_PID" > "$PIDFILE"
	echo "$pids" > /tmp/perf-drain.criu_pids
	echo "perf-drain: perf record started (pid $PERF_PID)" >&2

	# Also run perf stat for hardware counters (IPC, cache misses)
	"$PERF" stat -e cycles,instructions,cache-references,cache-misses,LLC-loads,LLC-load-misses,L1-dcache-loads,L1-dcache-load-misses -p "$pids" -o "$STAT_OUT" 2>/dev/null &
	STAT_PID=$!
	echo "perf-drain: perf stat started (pid $STAT_PID)" >&2
}

verify_criu_in_capture() {
	# Post-capture sanity: list the top PIDs present in the perf.data and
	# check that at least one of the criu PIDs we recorded is among them.
	local expected=""
	[ -r /tmp/perf-drain.criu_pids ] && expected=$(cat /tmp/perf-drain.criu_pids)

	echo "perf-drain: --- top processes in capture ---" >&2
	# perf report -s comm,pid: samples grouped by (process, pid)
	"$PERF" report -i "$OUT" --stdio -s comm,pid --no-children 2>/dev/null | \
		awk '/^[[:space:]]*[0-9]/{print} /^#/{next}' | head -15 >&2 || true
	echo "perf-drain: -----------------------------------" >&2

	if [ -n "$expected" ]; then
		local found=0 pid
		for pid in $(echo "$expected" | tr , ' '); do
			if "$PERF" script -i "$OUT" --pid="$pid" 2>/dev/null | head -1 | grep -q .; then
				echo "perf-drain: VERIFIED criu pid $pid has samples in capture" >&2
				found=1
				break
			fi
		done
		if [ "$found" -eq 0 ]; then
			echo "perf-drain: WARNING - none of the recorded criu PIDs ($expected) appear in the capture" >&2
			echo "perf-drain:   (criu may have exited before/during record, or was idle the whole window)" >&2
		fi
	fi
}

analyze_thread_balance() {
	# Parse drain thread progress from the log to check balance
	echo "perf-drain: --- drain thread balance analysis ---" >&2

	# Extract final drained count per thread (the last "drained=X" for each thread)
	# Pattern: "Drain thread N: drained=X" or "Drain thread N finished: drained=X"
	grep -E 'Drain thread [0-9]+.*(drained|finished)' "$LOG" 2>/dev/null | \
		grep -oE 'Drain thread [0-9]+[^0-9]*(drained|finished)[^0-9]*[0-9]+' | \
		sed 's/Drain thread \([0-9]*\).*[^0-9]\([0-9]*\)$/\1 \2/' | \
		sort -t' ' -k1,1n | \
		awk '
		{
			thread[$1] = $2  # Keep last value for each thread
		}
		END {
			if (length(thread) == 0) {
				print "No drain thread data found in log"
				exit
			}

			total = 0
			min = -1
			max = 0
			count = 0

			for (t in thread) {
				v = thread[t]
				total += v
				count++
				if (min < 0 || v < min) min = v
				if (v > max) max = v
			}

			avg = total / count
			imbalance = (max > 0) ? ((max - min) / max * 100) : 0

			printf "\nThread summary (%d threads):\n", count
			printf "  Total drained: %d pages\n", total
			printf "  Average per thread: %.0f pages\n", avg
			printf "  Min: %d, Max: %d\n", min, max
			printf "  Imbalance: %.1f%% (lower is better)\n", imbalance

			if (imbalance > 20) {
				printf "  WARNING: Significant thread imbalance detected!\n"
			} else if (imbalance > 10) {
				printf "  NOTE: Moderate thread imbalance.\n"
			} else {
				printf "  OK: Threads are well balanced.\n"
			}

			printf "\nPer-thread breakdown:\n"
			for (t = 0; t < 50; t++) {
				if (t in thread) {
					pct = (avg > 0) ? (thread[t] / avg * 100) : 0
					bar = ""
					bars = int(pct / 5)
					for (i = 0; i < bars && i < 30; i++) bar = bar "#"
					printf "  Thread %2d: %8d pages (%5.1f%% of avg) %s\n", t, thread[t], pct, bar
				}
			}
		}
		' > "$THREAD_BALANCE" 2>&1

	cat "$THREAD_BALANCE" >&2
	echo "perf-drain: ----------------------------------------" >&2
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
	echo "perf-drain: stopped. Output: $OUT" >&2
	if [ -s "$OUT" ]; then
		verify_criu_in_capture
	fi
	if [ -s "$STAT_OUT" ]; then
		echo "perf-drain: --- hardware counters ---" >&2
		cat "$STAT_OUT" >&2
		echo "perf-drain: ---" >&2
	fi

	# Analyze thread balance
	analyze_thread_balance

	echo "perf-drain: inspect ->" >&2
	echo "  sudo $PERF report -i $OUT -g graph,0.5,caller --stdio | head -100" >&2
	echo "  sudo $PERF script -i $OUT | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > /tmp/drain.svg" >&2
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
			echo "perf-drain: fixed ${FIXED_DURATION}s duration reached" >&2
			stop_perf
			break
		fi
		if [ "$elapsed" -ge "$MAX_SECONDS" ]; then
			echo "perf-drain: MAX_SECONDS ($MAX_SECONDS) reached without END match - stopping anyway" >&2
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
			echo "perf-drain: START matched: $line" >&2
			START_EPOCH=$(date +%s)
			if ! start_perf; then
				echo "perf-drain: start_perf failed - aborting" >&2
				exit 2
			fi
		fi
	else
		# If -d was given, ignore END_RE; stop only on duration.
		if [ "$FIXED_DURATION" -eq 0 ] && echo "$line" | grep -qE "$END_RE"; then
			echo "perf-drain: END matched: $line" >&2
			stop_perf
			break
		fi
	fi
done

exec 3<&-
