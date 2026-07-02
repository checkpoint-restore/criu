#!/bin/bash
#
# perf-migration.sh - Simple profiler for CRIU CLONE migration.
#
# Run this BEFORE starting the migration, then run your migration script.
# The profiler records system-wide until the migration completes or timeout.
#
# Usage:
#   sudo ./perf-migration.sh                    # Profile for 60s (default)
#   sudo ./perf-migration.sh -d 120             # Profile for 120s
#   sudo ./perf-migration.sh -d 120 -o /tmp/my  # Custom output dir
#
# Output:
#   /tmp/perf-migration/perf.data       - perf recording
#   /tmp/perf-migration/stat.txt        - hardware counters
#   /tmp/perf-migration/flamegraph.svg  - flame graph (if FlameGraph installed)
#   /tmp/perf-migration/report.txt      - top functions
#

set -u

# Find perf binary
PERF=/usr/lib/linux-tools-6.8.0-117/perf
if [ ! -x "$PERF" ]; then
    for p in /usr/lib/linux-tools/*/perf /usr/bin/perf perf; do
        if [ -x "$p" ] 2>/dev/null; then
            PERF="$p"
            break
        fi
    done
fi

DURATION=60
OUTDIR=/tmp/perf-migration
CRIU_PROCNAME=criu

while getopts "d:o:h" opt; do
    case "$opt" in
    d) DURATION=$OPTARG ;;
    o) OUTDIR=$OPTARG ;;
    h)
        sed -n '2,18p' "$0"
        exit 0
        ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "perf-migration: must run as root" >&2
    exit 1
fi

if [ -z "$PERF" ] || [ ! -x "$PERF" ]; then
    echo "perf-migration: perf not found" >&2
    exit 1
fi

mkdir -p "$OUTDIR"
OUT="$OUTDIR/perf.data"
STAT_OUT="$OUTDIR/stat.txt"
REPORT="$OUTDIR/report.txt"
FLAMEGRAPH="$OUTDIR/flamegraph.svg"

rm -f "$OUT" "$STAT_OUT" "$REPORT" "$FLAMEGRAPH"

echo "=============================================="
echo "  CRIU CLONE Migration Profiler"
echo "=============================================="
echo "Duration: ${DURATION}s"
echo "Output:   $OUTDIR"
echo ""
echo "Starting system-wide profiling..."
echo "Run your migration now!"
echo ""

# Start perf record
"$PERF" record -F 999 -g -a -o "$OUT" &
PERF_PID=$!

# Start perf stat (will attach to criu when it appears)
(
    # Wait for criu to start
    for _ in $(seq 1 "$DURATION"); do
        pids=$(pgrep -d, -x "$CRIU_PROCNAME" 2>/dev/null || true)
        if [ -n "$pids" ]; then
            "$PERF" stat -e cycles,instructions,cache-references,cache-misses,LLC-loads,LLC-load-misses -p "$pids" -o "$STAT_OUT" 2>/dev/null &
            STAT_PID=$!
            sleep "$DURATION"
            kill -INT "$STAT_PID" 2>/dev/null || true
            break
        fi
        sleep 1
    done
) &
STAT_MONITOR=$!

# Wait for duration
echo "Profiling for ${DURATION}s... (Ctrl+C to stop early)"
sleep "$DURATION" || true

# Stop perf
kill -INT "$PERF_PID" 2>/dev/null
wait "$PERF_PID" 2>/dev/null || true
kill "$STAT_MONITOR" 2>/dev/null || true

echo ""
echo "Profiling complete. Generating reports..."

# Generate report
echo "=== Top Functions ===" > "$REPORT"
"$PERF" report -i "$OUT" --stdio -g none --no-children 2>/dev/null | head -50 >> "$REPORT"

echo "" >> "$REPORT"
echo "=== Top Functions with Call Graph ===" >> "$REPORT"
"$PERF" report -i "$OUT" --stdio -g graph,0.5,caller --no-children 2>/dev/null | head -100 >> "$REPORT"

# Generate flamegraph
for dir in ~/FlameGraph /opt/FlameGraph /usr/local/FlameGraph; do
    if [ -x "$dir/stackcollapse-perf.pl" ] && [ -x "$dir/flamegraph.pl" ]; then
        echo "Generating flamegraph..."
        "$PERF" script -i "$OUT" 2>/dev/null | "$dir/stackcollapse-perf.pl" | "$dir/flamegraph.pl" > "$FLAMEGRAPH" 2>/dev/null
        break
    fi
done

echo ""
echo "=============================================="
echo "  Results"
echo "=============================================="
echo "Perf data:   $OUT"
echo "Report:      $REPORT"
[ -s "$STAT_OUT" ] && echo "HW counters: $STAT_OUT"
[ -s "$FLAMEGRAPH" ] && echo "Flamegraph:  $FLAMEGRAPH"
echo ""
echo "Interactive analysis:"
echo "  sudo $PERF report -i $OUT"
echo ""

# Show quick summary
echo "=== Quick Summary ==="
head -30 "$REPORT"

if [ -s "$STAT_OUT" ]; then
    echo ""
    echo "=== Hardware Counters ==="
    cat "$STAT_OUT"
fi
