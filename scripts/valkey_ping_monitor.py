#!/usr/bin/env python3
import argparse
import signal
import socket
import sys
import time
from select import select


PING_CMD = b"*1\r\n$4\r\nPING\r\n"


class StopRequested(Exception):
    pass


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Low-overhead Valkey PING monitor using a persistent TCP connection. "
            "Writes one line per request: send_ns recv_ns rtt_us STATUS"
        )
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6379)
    parser.add_argument("--interval-ms", type=float, default=5.0)
    parser.add_argument("--timeout-ms", type=float, default=10000.0)
    parser.add_argument("--out", required=True)
    return parser.parse_args()


def _connect(host: str, port: int, timeout_s: float) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(timeout_s)
    s.connect((host, port))
    s.settimeout(None)
    return s


def _recv_line(sock: socket.socket, timeout_s: float) -> bytes:
    buf = bytearray()
    deadline = time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timeout waiting for reply")

        r, _, _ = select([sock], [], [], remaining)
        if not r:
            raise TimeoutError("timeout waiting for reply")

        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
        if b"\r\n" in buf:
            line, _, _rest = buf.partition(b"\r\n")
            return bytes(line)


def main() -> int:
    args = _parse_args()
    interval_s = max(0.0, args.interval_ms / 1000.0)
    timeout_s = max(0.001, args.timeout_ms / 1000.0)

    stop = False

    def _handle_stop(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    # Line-buffered output; keep it readable for shell tooling.
    try:
        out_f = open(args.out, "w", buffering=1, encoding="utf-8")
    except OSError as e:
        print(f"ERROR: cannot open output file {args.out}: {e}", file=sys.stderr)
        return 2

    sock: socket.socket | None = None
    backoff_s = 0.05

    try:
        while not stop:
            if sock is None:
                try:
                    sock = _connect(args.host, args.port, timeout_s)
                    backoff_s = 0.05
                except OSError:
                    time.sleep(backoff_s)
                    backoff_s = min(1.0, backoff_s * 2)
                    continue

            send_ns = time.time_ns()
            try:
                sock.sendall(PING_CMD)
                _line = _recv_line(sock, timeout_s)
                recv_ns = time.time_ns()
                rtt_us = (recv_ns - send_ns) // 1000
                out_f.write(f"{send_ns} {recv_ns} {rtt_us} OK\n")
            except TimeoutError:
                recv_ns = time.time_ns()
                rtt_us = (recv_ns - send_ns) // 1000
                out_f.write(f"{send_ns} 0 {rtt_us} TIMEOUT\n")
                try:
                    sock.close()
                except OSError:
                    pass
                sock = None
            except (ConnectionError, OSError):
                recv_ns = time.time_ns()
                rtt_us = (recv_ns - send_ns) // 1000
                out_f.write(f"{send_ns} 0 {rtt_us} ERROR\n")
                try:
                    sock.close()
                except OSError:
                    pass
                sock = None

            if interval_s > 0:
                time.sleep(interval_s)
    finally:
        try:
            if sock is not None:
                sock.close()
        except OSError:
            pass
        out_f.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

