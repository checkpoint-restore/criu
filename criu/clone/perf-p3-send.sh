#!/bin/bash
#
# perf-p3-send.sh - Profile CRIU CLONE dump during P3 (bulk send) phase.
#
# Profiles the PRIMARY/dump side during data transfer (the slow part).
# Starts when P3 threads begin, stops when bulk transfer completes.
#
# Usage:
#   Shell A: sudo ./perf-p3-send.sh
#   Shell B: run your migration (migrate_new.sh)
#
#   Options:
#     -l <logfile>   Log file (default: /dev/shm/criu-migrate/lazy-primary.log)
#     -d <seconds>   Fixed duration (ignore END marker)
#     -P             Per-pid mode (default: system-wide)
#     -o <outdir>    Output directory (default: /tmp/perf-p3-send)
#

set -u

PERF=/usr/lib/linux-tools-6.8.0-117/perf
LOG=/dev/shm/criu-migrate/lazy-primary.log
OUTDIR=/tmp/perf-p3-send
FIXED_DURATION=0
PER_PID_MODE=0
MAX_SECONDS=300
CRIU_PROCNAME=criu

while getopts "l:d:Po:h" opt; do
    case "$opt" in
    l) LOG=$OPTARG ;;
    d) FIXED_DURATION=$OPTARG ;;
    P) PER_PID_MODE=1 ;;
    o) OUTDIR=$OPTARG ;;
    h)
        sed -n '2,18p' "$0"
        exit 0
        ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "perf-p3-send: must run as root" >&2
    exit 1
fi
if [ ! -x "$PERF" ]; then
    echo "perf-p3-send: perf not found at $PERF" >&2
    exit 1
fi

# Start marker: P3 threads starting or bulk transfer beginning
# Match actual log messages like:
#   "Starting 4 P3 bulk sender threads"
#   "P3[0]: Starting bulk transfer"
START_RE='Starting [0-9]+ P3|P3\[0\]: Starting bulk|Starting bulk transfer|clone_start_p3_threads'

# End marker: ALL P3 threads done (not individual thread completion)
# Key message: "all sender threads completed bulk transfer" from scanner
# Avoid matching individual "P3[N] done" or "Bulk transfer done" from single threads
END_RE='all sender threads completed bulk|All P3 threads done|clone_wait_p3_threads took|P3 TIMING from freeze'

mkdir -p "$OUTDIR"
OUT="$OUTDIR/perf.data"
STAT_OUT="$OUTDIR/stat.txt"
REPORT="$OUTDIR/report.txt"
FLAMEGRAPH="$OUTDIR/flamegraph.svg"
PIDFILE="$OUTDIR/perf.pid"

rm -f "$OUT" "$STAT_OUT" "$REPORT" "$FLAMEGRAPH" "$PIDFILE"

PERF_PID=0
STAT_PID=0
TAIL_PID=0
START_EPOCH=0

cleanup() {
    if [ -f "$PIDFILE" ]; then
        local pid
        pid=$(cat "$PIDFILE" 2>/dev/null || true)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -INT "$pid" 2>/dev/null
            sleep 2
            kill -KILL "$pid" 2>/dev/null || true
        fi
        rm -f "$PIDFILE"
    fi
    [ "$STAT_PID" -gt 0 ] && kill -INT "$STAT_PID" 2>/dev/null || true
    [ "$TAIL_PID" -gt 0 ] && kill "$TAIL_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

resolve_criu_pids() {
    pgrep -d, -x "$CRIU_PROCNAME" 2>/dev/null || true
}

start_perf() {
    local pids
    pids=$(resolve_criu_pids)

    echo "perf-p3-send: criu PIDs: ${pids:-none}" >&2
    [ -n "$pids" ] && ps -o pid,ppid,cmd -p "$(echo "$pids" | tr , ' ')" >&2 || true

    if [ "$PER_PID_MODE" -eq 1 ] && [ -n "$pids" ]; then
        "$PERF" record -F 999 -g -p "$pids" -o "$OUT" 2>/dev/null &
    else
        "$PERF" record -F 999 -g -a -o "$OUT" 2>/dev/null &
    fi
    PERF_PID=$!
    echo "$PERF_PID" > "$PIDFILE"
    echo "perf-p3-send: perf record started (pid $PERF_PID)" >&2

    if [ -n "$pids" ]; then
        "$PERF" stat -e cycles,instructions,cache-references,cache-misses,LLC-loads,LLC-load-misses,L1-dcache-loads,L1-dcache-load-misses -p "$pids" -o "$STAT_OUT" 2>/dev/null &
        STAT_PID=$!
    fi
}

stop_perf() {
    local duration=$(($(date +%s) - START_EPOCH))

    [ "$PERF_PID" -gt 0 ] && kill -INT "$PERF_PID" 2>/dev/null && wait "$PERF_PID" 2>/dev/null
    [ "$STAT_PID" -gt 0 ] && kill -INT "$STAT_PID" 2>/dev/null && wait "$STAT_PID" 2>/dev/null
    rm -f "$PIDFILE"

    echo "" >&2
    echo "=============================================" >&2
    echo "  P3 Send Phase Profiling Complete" >&2
    echo "=============================================" >&2
    echo "Duration: ${duration}s" >&2
    echo "Output:   $OUT" >&2

    # Generate report
    if [ -s "$OUT" ]; then
        echo "" >&2
        echo "=== Top Functions ===" >&2
        "$PERF" report -i "$OUT" --stdio -g none --no-children 2>/dev/null | head -30 | tee "$REPORT" >&2

        # CPU vs IO analysis: look at top functions
        echo "" >&2
        echo "=== CPU-bound Analysis ===" >&2

        # Extract overhead percentages for key functions
        local lz4_pct io_pct
        lz4_pct=$("$PERF" report -i "$OUT" --stdio -g none 2>/dev/null | grep -i 'lz4\|compress' | head -1 | awk '{print $1}' | tr -d '%')
        io_pct=$("$PERF" report -i "$OUT" --stdio -g none 2>/dev/null | grep -iE 'poll|epoll|futex|schedule|wait|__read|__write|tcp_send' | awk '{sum += $1} END {print sum}')

        echo "  LZ4/compress overhead: ${lz4_pct:-0}%" >&2
        echo "  IO/wait overhead:      ${io_pct:-0}%" >&2

        if [ -n "$lz4_pct" ] && [ "${lz4_pct%.*}" -ge 40 ]; then
            echo "  => CPU-BOUND by compression (LZ4 dominates)" >&2
        elif [ -n "$io_pct" ] && [ "${io_pct%.*}" -ge 30 ]; then
            echo "  => IO-BOUND (significant wait time)" >&2
        else
            echo "  => Check flamegraph for details" >&2
        fi

        # Try flamegraph
        for dir in ~/FlameGraph /opt/FlameGraph /usr/local/FlameGraph; do
            if [ -x "$dir/stackcollapse-perf.pl" ]; then
                "$PERF" script -i "$OUT" 2>/dev/null | "$dir/stackcollapse-perf.pl" | "$dir/flamegraph.pl" > "$FLAMEGRAPH" 2>/dev/null
                [ -s "$FLAMEGRAPH" ] && echo "Flamegraph: $FLAMEGRAPH" >&2
                break
            fi
        done
    fi

    if [ -s "$STAT_OUT" ]; then
        echo "" >&2
        echo "=== Hardware Counters ===" >&2
        cat "$STAT_OUT" >&2

        # Extract IPC from perf stat output (format: "# X.XX insn per cycle")
        local ipc
        ipc=$(grep -oP '[0-9]+\.[0-9]+\s+insn per cycle' "$STAT_OUT" | grep -oP '^[0-9.]+' | head -1)
        if [ -n "$ipc" ]; then
            echo "" >&2
            echo "  IPC (instructions/cycle): $ipc" >&2
            echo "    IPC > 1.0 = good CPU utilization" >&2
            echo "    IPC < 0.5 = likely memory/cache bound" >&2
        fi
    fi

    echo "" >&2
    echo "Interactive: sudo $PERF report -i $OUT" >&2
}

# Main
echo "perf-p3-send: Profiling P3 send phase (PRIMARY/dump side)" >&2
echo "perf-p3-send: Log: $LOG" >&2
echo "perf-p3-send: START: $START_RE" >&2
echo "perf-p3-send: END: $END_RE" >&2
echo "perf-p3-send: Waiting for log file..." >&2

while [ ! -r "$LOG" ]; do sleep 0.5; done
echo "perf-p3-send: Log ready, waiting for START marker..." >&2

# Check if START marker already exists in log (migration already started)
if grep -qE "$START_RE" "$LOG" 2>/dev/null; then
    echo "perf-p3-send: START marker already in log, checking if still in progress..." >&2
    if grep -qE "$END_RE" "$LOG" 2>/dev/null; then
        echo "perf-p3-send: ERROR - migration already completed (END marker found)" >&2
        echo "perf-p3-send: Start this script BEFORE running migration" >&2
        exit 1
    fi
    # Migration in progress - start profiling immediately
    echo "perf-p3-send: Migration in progress, starting perf NOW" >&2
    START_EPOCH=$(date +%s)
    start_perf
fi

exec 3< <(exec tail -n0 -F "$LOG" 2>/dev/null)
TAIL_PID=$!

while :; do
    if [ "$PERF_PID" -gt 0 ]; then
        elapsed=$(($(date +%s) - START_EPOCH))
        if [ "$FIXED_DURATION" -gt 0 ] && [ "$elapsed" -ge "$FIXED_DURATION" ]; then
            echo "perf-p3-send: duration reached" >&2
            stop_perf; break
        fi
        if [ "$elapsed" -ge "$MAX_SECONDS" ]; then
            echo "perf-p3-send: timeout" >&2
            stop_perf; break
        fi
    fi

    if ! IFS= read -r -t 1 -u 3 line; then continue; fi

    if [ "$PERF_PID" -eq 0 ]; then
        if echo "$line" | grep -qEi "$START_RE"; then
            echo "perf-p3-send: START: $line" >&2
            START_EPOCH=$(date +%s)
            start_perf
        fi
    else
        if [ "$FIXED_DURATION" -eq 0 ] && echo "$line" | grep -qEi "$END_RE"; then
            echo "perf-p3-send: END: $line" >&2
            stop_perf; break
        fi
    fi
done

exec 3<&-
