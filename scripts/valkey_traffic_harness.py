#!/usr/bin/env python3
import argparse
import hashlib
import json
import random
import signal
import socket
import statistics
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


class ValkeyError(Exception):
    pass


class ValkeyConn:
    def __init__(self, host: str, port: int, timeout: float):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _connect(self) -> None:
        if self.sock is not None:
            return
        self.sock = socket.create_connection(
            (self.host, self.port),
            timeout=self.timeout,
        )
        self.sock.settimeout(self.timeout)

    def _read_exact(self, length: int) -> bytes:
        assert self.sock is not None
        data = bytearray()
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("socket closed")
            data.extend(chunk)
        return bytes(data)

    def _read_line(self) -> bytes:
        assert self.sock is not None
        buf = bytearray()
        while True:
            chunk = self.sock.recv(1)
            if not chunk:
                raise ConnectionError("socket closed")
            buf.extend(chunk)
            if len(buf) >= 2 and buf[-2:] == b"\r\n":
                return bytes(buf[:-2])

    def _read_resp(self):
        line = self._read_line()
        if not line:
            raise ConnectionError("empty response")

        prefix = line[:1]
        payload = line[1:]

        if prefix == b"+":
            return payload.decode("utf-8", errors="replace")
        if prefix == b":":
            return int(payload)
        if prefix == b"$":
            length = int(payload)
            if length == -1:
                return None
            body = self._read_exact(length)
            crlf = self._read_exact(2)
            if crlf != b"\r\n":
                raise ConnectionError("invalid bulk termination")
            return body
        if prefix == b"-":
            raise ValkeyError(payload.decode("utf-8", errors="replace"))
        if prefix == b"*":
            count = int(payload)
            if count == -1:
                return None
            return [self._read_resp() for _ in range(count)]
        raise ConnectionError(f"unknown RESP prefix: {prefix!r}")

    def command(self, *parts: str):
        buf = [f"*{len(parts)}\r\n".encode()]
        for part in parts:
            if isinstance(part, bytes):
                value = part
            else:
                value = str(part).encode()
            buf.append(f"${len(value)}\r\n".encode())
            buf.append(value + b"\r\n")
        frame = b"".join(buf)

        try:
            self._connect()
            assert self.sock is not None
            self.sock.sendall(frame)
            return self._read_resp()
        except (OSError, TimeoutError, ConnectionError):
            self.close()
            raise
        except ValkeyError:
            raise


@dataclass
class OpStats:
    total: int = 0
    success: int = 0
    errors: int = 0
    latencies_ms: List[float] = field(default_factory=list)
    outage_open_at: Optional[float] = None
    outages_ms: List[float] = field(default_factory=list)

    def record(self, ok: bool, latency_ms: float, now: float, track_outage: bool = True) -> None:
        self.total += 1
        if ok:
            self.success += 1
            self.latencies_ms.append(latency_ms)
            if self.outage_open_at is not None:
                self.outages_ms.append((now - self.outage_open_at) * 1000.0)
                self.outage_open_at = None
            return

        self.errors += 1
        if track_outage and self.outage_open_at is None:
            self.outage_open_at = now

    def close_open_outage(self, now: float) -> None:
        if self.outage_open_at is not None:
            self.outages_ms.append((now - self.outage_open_at) * 1000.0)
            self.outage_open_at = None

    def summary(self) -> Dict[str, float]:
        lat = sorted(self.latencies_ms)
        outages = sorted(self.outages_ms)

        def percentile(values: List[float], pct: float) -> float:
            if not values:
                return 0.0
            idx = int(round((pct / 100.0) * (len(values) - 1)))
            return values[idx]

        return {
            "total": self.total,
            "success": self.success,
            "errors": self.errors,
            "success_rate": (self.success / self.total) if self.total else 0.0,
            "latency_ms_p50": percentile(lat, 50),
            "latency_ms_p95": percentile(lat, 95),
            "latency_ms_p99": percentile(lat, 99),
            "latency_ms_avg": statistics.mean(lat) if lat else 0.0,
            "max_outage_ms": max(outages) if outages else 0.0,
            "outage_events": len(outages),
        }


class Harness:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.stop_event = threading.Event()
        self.started_at = time.time()

        self.metrics = {
            "source_write": OpStats(),
            "source_read": OpStats(),
            "replica_read": OpStats(),
            "replica_write_attempt": OpStats(),
        }

        self.expected_lock = threading.Lock()
        self.expected_values: Dict[str, str] = {}

        self.replica_write_rejected = 0
        self.replica_write_accepted = 0
        self.replica_write_lock = threading.Lock()

    def stop(self) -> None:
        self.stop_event.set()

    def _key(self, idx: int) -> str:
        return f"{self.args.key_prefix}:{idx}"

    def _random_key(self, rnd: random.Random) -> str:
        return self._key(rnd.randrange(self.args.keyspace))

    def _record(self, metric: str, ok: bool, start: float, track_outage: bool = True) -> None:
        now = time.time()
        latency_ms = (now - start) * 1000.0
        self.metrics[metric].record(ok, latency_ms, now, track_outage=track_outage)

    def _source_writer(self, worker_id: int) -> None:
        rnd = random.Random(0xA5A50000 + worker_id)
        conn = ValkeyConn(self.args.source_host, self.args.source_port, self.args.socket_timeout)
        seq = 0
        while not self.stop_event.is_set():
            key = self._random_key(rnd)
            value = f"{worker_id}:{seq}:{rnd.getrandbits(64):016x}"
            start = time.time()
            try:
                resp = conn.command("SET", key, value)
                ok = isinstance(resp, str) and resp.upper() == "OK"
                if ok:
                    with self.expected_lock:
                        self.expected_values[key] = value
            except Exception:
                ok = False
            self._record("source_write", ok, start, track_outage=True)
            seq += 1

    def _source_reader(self, worker_id: int) -> None:
        rnd = random.Random(0x5AA50000 + worker_id)
        conn = ValkeyConn(self.args.source_host, self.args.source_port, self.args.socket_timeout)
        while not self.stop_event.is_set():
            key = self._random_key(rnd)
            start = time.time()
            try:
                conn.command("GET", key)
                ok = True
            except Exception:
                ok = False
            self._record("source_read", ok, start, track_outage=True)

    def _replica_reader(self, worker_id: int) -> None:
        rnd = random.Random(0xC3C30000 + worker_id)
        conn = ValkeyConn(self.args.replica_host, self.args.replica_port, self.args.socket_timeout)
        while not self.stop_event.is_set():
            key = self._random_key(rnd)
            start = time.time()
            try:
                conn.command("GET", key)
                ok = True
            except Exception:
                ok = False
            self._record("replica_read", ok, start, track_outage=True)

    def _replica_write_probe(self, worker_id: int) -> None:
        rnd = random.Random(0xD4D40000 + worker_id)
        conn = ValkeyConn(self.args.replica_host, self.args.replica_port, self.args.socket_timeout)
        while not self.stop_event.is_set():
            key = self._random_key(rnd)
            value = f"replica-probe:{worker_id}:{rnd.getrandbits(32):08x}"
            start = time.time()
            ok = False
            track_outage = True
            try:
                resp = conn.command("SET", key, value)
                if isinstance(resp, str) and resp.upper() == "OK":
                    with self.replica_write_lock:
                        self.replica_write_accepted += 1
                ok = True
            except ValkeyError as err:
                msg = str(err).upper()
                if "READONLY" in msg:
                    with self.replica_write_lock:
                        self.replica_write_rejected += 1
                    ok = True
                    track_outage = False
            except Exception:
                ok = False
            self._record("replica_write_attempt", ok, start, track_outage=track_outage)

    def _parse_info(self, payload: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for line in payload.splitlines():
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            out[key.strip()] = value.strip()
        return out

    def _get_int(self, info: Dict[str, str], *keys: str, default: int = 0) -> int:
        for key in keys:
            value = info.get(key)
            if value is None:
                continue
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
        return default

    def _wait_replica_caught_up(self) -> Tuple[bool, Dict[str, object]]:
        src = ValkeyConn(self.args.source_host, self.args.source_port, self.args.socket_timeout)
        dst = ValkeyConn(self.args.replica_host, self.args.replica_port, self.args.socket_timeout)
        deadline = time.time() + self.args.catchup_timeout
        last: Dict[str, object] = {
            "source_repl_offset": -1,
            "replica_repl_offset": -1,
            "source_role": "unknown",
            "replica_role": "unknown",
            "replica_link_status": "down",
        }
        while time.time() < deadline:
            try:
                src_info_raw = src.command("INFO", "replication")
                dst_info_raw = dst.command("INFO", "replication")
                if not isinstance(src_info_raw, bytes) or not isinstance(dst_info_raw, bytes):
                    time.sleep(0.1)
                    continue
                src_info = self._parse_info(src_info_raw.decode("utf-8", errors="replace"))
                dst_info = self._parse_info(dst_info_raw.decode("utf-8", errors="replace"))
                source_repl_offset = self._get_int(src_info, "master_repl_offset")
                replica_repl_offset = self._get_int(
                    dst_info,
                    "replica_repl_offset",
                    "master_repl_offset",
                )
                replica_link_status = dst_info.get("master_link_status", "down")
                last = {
                    "source_repl_offset": source_repl_offset,
                    "replica_repl_offset": replica_repl_offset,
                    "source_role": src_info.get("role", "unknown"),
                    "replica_role": dst_info.get("role", "unknown"),
                    "replica_link_status": replica_link_status,
                }
                if replica_link_status == "up" and replica_repl_offset >= source_repl_offset:
                    return True, last
            except Exception:
                pass
            time.sleep(0.1)
        return False, last

    def _fetch_value(self, conn: ValkeyConn, key: str) -> Optional[bytes]:
        resp = conn.command("GET", key)
        if resp is None:
            return None
        if isinstance(resp, bytes):
            return resp
        return str(resp).encode()

    def _run_data_checks(self) -> Dict[str, object]:
        source = ValkeyConn(self.args.source_host, self.args.source_port, self.args.socket_timeout)
        replica = ValkeyConn(self.args.replica_host, self.args.replica_port, self.args.socket_timeout)
        rnd = random.Random(0x77441122)
        deadline = time.time() + self.args.check_timeout

        sample_size = min(self.args.sample_size, self.args.keyspace)
        key_ids = list(range(self.args.keyspace))
        rnd.shuffle(key_ids)
        keys = [self._key(idx) for idx in key_ids[:sample_size]]

        source_digest = hashlib.sha256()
        replica_digest = hashlib.sha256()
        value_mismatches = 0
        compared = 0

        for key in keys:
            if time.time() >= deadline:
                break
            try:
                src_val = self._fetch_value(source, key)
                dst_val = self._fetch_value(replica, key)
            except Exception:
                value_mismatches += 1
                continue
            compared += 1
            source_digest.update(key.encode() + b"\0" + (src_val or b""))
            replica_digest.update(key.encode() + b"\0" + (dst_val or b""))
            if src_val != dst_val:
                value_mismatches += 1

        with self.expected_lock:
            expected_items = list(self.expected_values.items())
        rnd.shuffle(expected_items)
        expected_items = expected_items[: self.args.expected_check_limit]

        source_expected_mismatch = 0
        replica_expected_mismatch = 0
        expected_checked_actual = 0
        for key, value in expected_items:
            if time.time() >= deadline:
                break
            expected_checked_actual += 1
            expected = value.encode()
            try:
                src_val = self._fetch_value(source, key)
                dst_val = self._fetch_value(replica, key)
            except Exception:
                source_expected_mismatch += 1
                replica_expected_mismatch += 1
                continue
            if src_val != expected:
                source_expected_mismatch += 1
            if dst_val != expected:
                replica_expected_mismatch += 1

        return {
            "sampled_keys": sample_size,
            "sampled_compared": compared,
            "checks_timed_out": time.time() >= deadline,
            "sample_value_mismatches": value_mismatches,
            "source_sample_digest": source_digest.hexdigest(),
            "replica_sample_digest": replica_digest.hexdigest(),
            "expected_checked": expected_checked_actual,
            "source_expected_mismatches": source_expected_mismatch,
            "replica_expected_mismatches": replica_expected_mismatch,
        }

    def _status_line(self) -> str:
        sw = self.metrics["source_write"]
        sr = self.metrics["source_read"]
        rr = self.metrics["replica_read"]
        with self.replica_write_lock:
            rej = self.replica_write_rejected
            acc = self.replica_write_accepted
        return (
            f"uptime={time.time() - self.started_at:6.1f}s "
            f"src_w={sw.success}/{sw.total} src_r={sr.success}/{sr.total} "
            f"rep_r={rr.success}/{rr.total} rep_w_rej={rej} rep_w_acc={acc}"
        )

    def run(self) -> Dict[str, object]:
        threads: List[threading.Thread] = []

        for idx in range(self.args.source_writers):
            threads.append(threading.Thread(target=self._source_writer, args=(idx,), daemon=True))
        for idx in range(self.args.source_readers):
            threads.append(threading.Thread(target=self._source_reader, args=(idx,), daemon=True))
        for idx in range(self.args.replica_readers):
            threads.append(threading.Thread(target=self._replica_reader, args=(idx,), daemon=True))
        for idx in range(self.args.replica_writers):
            threads.append(threading.Thread(target=self._replica_write_probe, args=(idx,), daemon=True))

        for thread in threads:
            thread.start()

        deadline = time.time() + self.args.duration if self.args.duration > 0 else None
        next_status = time.time() + self.args.status_interval
        while not self.stop_event.is_set():
            now = time.time()
            if deadline is not None and now >= deadline:
                self.stop_event.set()
                break
            if self.args.status_interval > 0 and now >= next_status:
                print(self._status_line(), flush=True)
                next_status = now + self.args.status_interval
            time.sleep(0.05)

        for thread in threads:
            thread.join(timeout=2.0)

        now = time.time()
        for stat in self.metrics.values():
            stat.close_open_outage(now)

        replica_caught_up, offsets = self._wait_replica_caught_up()
        data_checks = self._run_data_checks()

        with self.replica_write_lock:
            replica_write_accepted = self.replica_write_accepted
            replica_write_rejected = self.replica_write_rejected

        report = {
            "duration_seconds": now - self.started_at,
            "args": {
                "source_host": self.args.source_host,
                "source_port": self.args.source_port,
                "replica_host": self.args.replica_host,
                "replica_port": self.args.replica_port,
                "keyspace": self.args.keyspace,
            },
            "metrics": {name: stat.summary() for name, stat in self.metrics.items()},
            "replica_write_rejected": replica_write_rejected,
            "replica_write_accepted": replica_write_accepted,
            "replication_caught_up": replica_caught_up,
            "replication_offsets": offsets,
            "data_checks": data_checks,
        }

        report["pass"] = (
            replica_write_accepted == 0
            and replica_caught_up
            and not data_checks["checks_timed_out"]
            and data_checks["sample_value_mismatches"] == 0
            and data_checks["source_expected_mismatches"] == 0
            and data_checks["replica_expected_mismatches"] == 0
        )
        return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Continuous Valkey traffic harness for migration correctness and downtime checks"
    )
    parser.add_argument("--source-host", default="127.0.0.1")
    parser.add_argument("--source-port", type=int, default=6379)
    parser.add_argument("--replica-host", required=True)
    parser.add_argument("--replica-port", type=int, default=6379)
    parser.add_argument("--duration", type=float, default=0.0, help="0 means run until SIGINT/SIGTERM")
    parser.add_argument("--socket-timeout", type=float, default=0.35)
    parser.add_argument("--status-interval", type=float, default=2.0)
    parser.add_argument("--key-prefix", default="hkey")
    parser.add_argument("--keyspace", type=int, default=100000)
    parser.add_argument("--sample-size", type=int, default=5000)
    parser.add_argument("--expected-check-limit", type=int, default=5000)
    parser.add_argument("--catchup-timeout", type=float, default=20.0)
    parser.add_argument("--check-timeout", type=float, default=15.0)
    parser.add_argument("--source-writers", type=int, default=4)
    parser.add_argument("--source-readers", type=int, default=8)
    parser.add_argument("--replica-readers", type=int, default=8)
    parser.add_argument("--replica-writers", type=int, default=2)
    parser.add_argument("--report", default="/tmp/valkey_traffic_harness_report.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    harness = Harness(args)

    def _sig_handler(_signum, _frame):
        harness.stop()

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    report = harness.run()

    with open(args.report, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)

    print(f"report={args.report}", flush=True)
    print(f"pass={report['pass']}", flush=True)
    print(
        "replica_write_accepted="
        f"{report['replica_write_accepted']} "
        f"sample_mismatches={report['data_checks']['sample_value_mismatches']} "
        f"max_src_write_outage_ms={report['metrics']['source_write']['max_outage_ms']:.3f} "
        f"max_src_read_outage_ms={report['metrics']['source_read']['max_outage_ms']:.3f} "
        f"max_replica_read_outage_ms={report['metrics']['replica_read']['max_outage_ms']:.3f}",
        flush=True,
    )

    return 0 if report["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
