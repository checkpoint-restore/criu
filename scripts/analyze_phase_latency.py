#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class PingSample:
    send_ms: int
    rtt_us: int
    status: str


@dataclass(frozen=True)
class Phase:
    name: str
    start_ms: int
    end_ms: int

    @property
    def duration_ms(self) -> int:
        return max(0, self.end_ms - self.start_ms)


def parse_markers(path: Path) -> dict[str, int]:
    markers: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        event, ts_ms_s = parts[0], parts[1]
        try:
            markers[event] = int(ts_ms_s)
        except ValueError:
            continue
    return markers


def parse_pings(path: Path) -> list[PingSample]:
    out: list[PingSample] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 4:
            continue
        try:
            send_ns = int(parts[0])
            rtt_us = int(parts[2])
        except ValueError:
            continue
        status = parts[3]
        out.append(
            PingSample(send_ms=send_ns // 1_000_000, rtt_us=rtt_us, status=status)
        )
    return out


def percentile_int(vals: list[int], q: float) -> int | None:
    if not vals:
        return None
    if q <= 0:
        return min(vals)
    if q >= 1:
        return max(vals)
    vals = sorted(vals)
    idx = (len(vals) - 1) * q
    lo = math.floor(idx)
    hi = math.ceil(idx)
    if lo == hi:
        return vals[lo]
    frac = idx - lo
    return int(round(vals[lo] * (1.0 - frac) + vals[hi] * frac))


def phase_summary(samples: Iterable[PingSample], phase: Phase) -> dict[str, object]:
    window = [s for s in samples if phase.start_ms <= s.send_ms < phase.end_ms]

    ok = [s for s in window if s.status == "OK"]
    ok_rtts = [s.rtt_us for s in ok]
    timeouts = sum(1 for s in window if s.status == "TIMEOUT")
    errors = sum(1 for s in window if s.status == "ERROR")

    max_ok = max(ok_rtts) if ok_rtts else None
    max_ok_at_ms = None
    if max_ok is not None:
        for s in ok:
            if s.rtt_us == max_ok:
                max_ok_at_ms = s.send_ms
                break

    return {
        "duration_ms": phase.duration_ms,
        "samples": len(window),
        "ok": len(ok_rtts),
        "timeouts": timeouts,
        "errors": errors,
        "ok_mean_us": int(round(statistics.mean(ok_rtts))) if ok_rtts else None,
        "ok_p50_us": percentile_int(ok_rtts, 0.50),
        "ok_p90_us": percentile_int(ok_rtts, 0.90),
        "ok_p99_us": percentile_int(ok_rtts, 0.99),
        "ok_max_us": max_ok,
        "ok_max_at_ms": max_ok_at_ms,
    }


def fmt_us(v: int | None) -> str:
    if v is None:
        return "-"
    if v >= 1000:
        return f"{v / 1000.0:.3f}ms"
    return f"{v}us"


def fmt_at(phase: Phase, ts_ms: int | None) -> str:
    if ts_ms is None:
        return "-"
    return f"+{ts_ms - phase.start_ms}ms"


def build_phases(markers: dict[str, int]) -> list[Phase]:
    phases: list[Phase] = []
    start = markers.get("SOURCE_PING_MONITOR_START_MS")
    stop = markers.get("SOURCE_PING_MONITOR_STOP_MS")
    if start is not None and stop is not None and stop > start:
        phases.append(Phase("total", start, stop))

    dump_launch = markers.get("DUMP_LAUNCH_MS")
    if start is not None and dump_launch is not None and dump_launch > start:
        phases.append(Phase("pre_dump", start, dump_launch))

    page_ready = markers.get("PAGE_SERVER_READY_MS")
    if dump_launch is not None and page_ready is not None and page_ready > dump_launch:
        phases.append(Phase("dump_until_ready", dump_launch, page_ready))

    cutover_start = markers.get("CUTOVER_START_MS")
    cutover_end = markers.get("CUTOVER_END_MS")

    if page_ready is not None and stop is not None and stop > page_ready:
        if cutover_start is not None and cutover_start > page_ready:
            phases.append(Phase("migration", page_ready, min(cutover_start, stop)))
        if (
            cutover_start is not None
            and cutover_end is not None
            and cutover_end > cutover_start
        ):
            phases.append(Phase("cutover", cutover_start, min(cutover_end, stop)))
        if cutover_end is not None and cutover_end < stop:
            phases.append(Phase("post_cutover", cutover_end, stop))
        if not any(p.name in {"migration", "cutover", "post_cutover"} for p in phases):
            phases.append(Phase("post_ready", page_ready, stop))

    return phases


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Analyze Valkey ping latency per phase for a migrate.sh run dir. "
            "Consumes source_markers.log + source-ping.log."
        )
    )
    p.add_argument("run_dir", help="Path to artifacts/<run_id> directory")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    run_dir = Path(args.run_dir)
    markers_path = run_dir / "source_markers.log"
    pings_path = run_dir / "source-ping.log"

    if not pings_path.exists():
        raise SystemExit(f"missing {pings_path}")

    samples = parse_pings(pings_path)
    markers: dict[str, int] = {}
    if markers_path.exists():
        markers = parse_markers(markers_path)

    phases = build_phases(markers)
    if not phases:
        phases = [Phase("total", samples[0].send_ms, samples[-1].send_ms + 1)]

    workload = "yes" if (run_dir / "workload.log").exists() else "no"
    print(f"Run: {run_dir}")
    print(f"Workload: {workload}")
    print("")

    for phase in phases:
        s = phase_summary(samples, phase)
        print(
            f"{phase.name} "
            f"dur={s['duration_ms']}ms "
            f"samples={s['samples']} ok={s['ok']} "
            f"to={s['timeouts']} err={s['errors']} | "
            f"OK mean={fmt_us(s['ok_mean_us'])} "
            f"p50={fmt_us(s['ok_p50_us'])} "
            f"p90={fmt_us(s['ok_p90_us'])} "
            f"p99={fmt_us(s['ok_p99_us'])} "
            f"max={fmt_us(s['ok_max_us'])}@{fmt_at(phase, s['ok_max_at_ms'])}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
