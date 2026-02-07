#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path
from typing import Dict, Optional


TIMING_PATTERNS = {
    "dump_one_task_total_s": re.compile(r"dump_one_task TOTAL took ([0-9]+\.[0-9]+)"),
    "parse_smaps_s": re.compile(r"parse_smaps took ([0-9]+\.[0-9]+)"),
    "dump_pages_seized_s": re.compile(r"parasite_dump_pages_seized took ([0-9]+\.[0-9]+)"),
    "generate_vma_iovs_s": re.compile(r"generate_vma_iovs loop took ([0-9]+\.[0-9]+)"),
}

ERROR_PATTERNS = {
    "page_server_start_read_errors": "page_server_start_read",
    "remote_closed_errors": "Remote side closed connection",
    "send_psi_errors": "Can't send PSI",
    "connection_reset_errors": "Connection reset by peer",
}


def read_text(path: Path) -> str:
    return path.read_bytes().decode("utf-8", errors="ignore")


def last_match_float(pattern: re.Pattern, text: str) -> Optional[float]:
    matches = pattern.findall(text)
    if not matches:
        return None
    return float(matches[-1])


def extract_primary_metrics(primary_log: Path) -> Dict[str, object]:
    text = read_text(primary_log)
    timings: Dict[str, Optional[float]] = {}
    for name, pattern in TIMING_PATTERNS.items():
        timings[name] = last_match_float(pattern, text)

    errors: Dict[str, int] = {}
    for name, token in ERROR_PATTERNS.items():
        errors[name] = text.count(token)

    return {
        "timings": timings,
        "errors": errors,
    }


def extract_harness_metrics(harness_report: Path) -> Dict[str, object]:
    report = json.loads(harness_report.read_text(encoding="utf-8"))
    metrics = report.get("metrics", {})
    cutover = report.get("cutover", {})
    gates = report.get("gates", {})
    data_checks = report.get("data_checks", {})
    source_write = metrics.get("source_write", {})
    source_read = metrics.get("source_read", {})
    replica_read = metrics.get("replica_read", {})

    return {
        "pass": bool(report.get("pass", False)),
        "replica_write_accepted": int(report.get("replica_write_accepted", 0)),
        "replication_caught_up": bool(report.get("replication_caught_up", False)),
        "sample_mismatches": int(data_checks.get("sample_value_mismatches", 0)),
        "touched_key_mismatches": int(data_checks.get("touched_key_mismatches", 0)),
        "source_write_p99_ms": float(source_write.get("latency_ms_p99", 0.0)),
        "source_read_p99_ms": float(source_read.get("latency_ms_p99", 0.0)),
        "replica_read_p99_ms": float(replica_read.get("latency_ms_p99", 0.0)),
        "source_write_max_outage_ms": float(source_write.get("max_outage_ms", 0.0)),
        "source_read_max_outage_ms": float(source_read.get("max_outage_ms", 0.0)),
        "replica_read_max_outage_ms": float(replica_read.get("max_outage_ms", 0.0)),
        "cutover_gate_ok": bool(gates.get("cutover_gate_ok", False)),
        "cutover_window_found": bool(cutover.get("window_found", False)),
        "cutover_window_ms": float(cutover.get("window_ms", 0.0)),
        "cutover_source_write_max_outage_ms": float(cutover.get("source_write_max_outage_ms", 0.0)),
        "cutover_source_read_max_outage_ms": float(cutover.get("source_read_max_outage_ms", 0.0)),
        "cutover_replica_read_max_outage_ms": float(cutover.get("replica_read_max_outage_ms", 0.0)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract CRIU-focused KPIs from scenario artifacts")
    parser.add_argument("--harness-report", required=True)
    parser.add_argument("--primary-log", required=True)
    parser.add_argument("--output", default="/tmp/criu_kpi_report.json")
    args = parser.parse_args()

    harness_report = Path(args.harness_report)
    primary_log = Path(args.primary_log)
    output = Path(args.output)

    result = {
        "harness": extract_harness_metrics(harness_report),
        "criu_primary": extract_primary_metrics(primary_log),
    }

    output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")

    print(f"kpi_report={output}")
    print(f"harness_pass={result['harness']['pass']}")
    print(f"cutover_gate_ok={result['harness']['cutover_gate_ok']}")
    print(
        "criu_dump_total_s="
        f"{result['criu_primary']['timings']['dump_one_task_total_s']} "
        "source_write_max_outage_ms="
        f"{result['harness']['source_write_max_outage_ms']:.3f} "
        "source_read_max_outage_ms="
        f"{result['harness']['source_read_max_outage_ms']:.3f} "
        "replica_read_max_outage_ms="
        f"{result['harness']['replica_read_max_outage_ms']:.3f} "
        "cutover_replica_read_max_outage_ms="
        f"{result['harness']['cutover_replica_read_max_outage_ms']:.3f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
