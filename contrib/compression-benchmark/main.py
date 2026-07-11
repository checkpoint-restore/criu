#!/usr/bin/env python3
"""
CRIU Memory Pages Compression Benchmark

Measures the performance and storage impact of CRIU's compression
options across different memory workload patterns.

Compression modes:
  uncompressed - No compression
  lz4-page    - Each host page compressed as its own LZ4 block
  lz4-region  - N consecutive pages compressed as a single LZ4 block
                (region size set via --region-sizes)

Workload patterns (defined in workload.py):
  zero    - All pages zero-filled (best case: highly compressible)
  mixed   - 50% zeros, 25% repeated data, 25% random (typical)
  random  - All pages random bytes (worst case: incompressible)
  text    - JSON-like ASCII text (real-world heap shape)
  elf     - Concatenated system binaries (binary blob shape)

Methodology:
  - Each configuration runs N iterations (default 3) + 1 warmup
  - Configuration order rotates between iterations to reduce host drift
  - Page cache is dropped between runs for consistent IO
  - Results show the median of measured iterations
  - Memory integrity validated via SHA-256 after each restore
  - For LZ4 region compression the benchmark sweeps multiple region sizes by
    default to expose the size/ratio/throughput tradeoff.

Usage:
  sudo python3 contrib/compression-benchmark/main.py
  sudo python3 contrib/compression-benchmark/main.py -n 5 -s 512
  sudo python3 contrib/compression-benchmark/main.py -p zero mixed random
  sudo python3 contrib/compression-benchmark/main.py \\
       --modes uncompressed lz4-page lz4-region \\
       --region-sizes 65536 262144 1048576
"""

import argparse
import contextlib
import json
import math
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time

# The workload module lives next to this script. fill_pattern() is the
# single source of truth for what bytes the workload writes to memory,
# so we import it both for spawning the workload (as a separate process)
# and for computing the expected SHA-256 the restore side must match.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import workload  # noqa: E402

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
MAX_REGION_SIZE = 4 * 1024 * 1024
MAX_COMPRESSION_ACCELERATION = 65537
MAX_DECOMPRESSION_THREADS = 1024
CHECKSUM_TIMEOUT = 60
WORKLOAD_START_MIN_TIMEOUT = 30
WORKLOAD_START_MIN_RATE = 64 * 1024 * 1024
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORKLOAD_PATH = os.path.join(SCRIPT_DIR, "workload.py")

PATTERN_DESCRIPTIONS = {
    "zero": "All pages zero-filled; highly compressible",
    "mixed": "50% zero, 25% repeated, 25% random; typical mixed memory",
    "random": "Pseudorandom pages; incompressible",
    "text": "Repeated JSON-like text; structured data",
    "elf": "Concatenated system binaries; binary data",
}

# The benchmark lives at contrib/compression-benchmark/, so the repo root
# is two directories up. Anchor the default criu binary and the pycriu
# library to it so the script works regardless of the current directory.
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
DEFAULT_CRIU = os.path.join(REPO_ROOT, "criu", "criu")


def decompress_threads_label(threads):
    """None uses CRIU's serial default; 0 is auto; positive values are explicit."""
    if threads is None:
        return "default (serial)"
    if threads == 0:
        return "auto"
    return str(threads)


def decompress_threads_args(threads):
    """Return the CRIU arguments for an explicitly selected thread count."""
    if threads is None:
        return []
    return ["--decompress-threads", str(threads)]


class RuntimeState:
    """Mutable process state shared by the benchmark's cleanup paths."""

    def __init__(self):
        self.criu_bin = DEFAULT_CRIU
        self.compress_acceleration = 1
        self.decompress_threads = None
        self.drop_caches = True
        self.pimg = None
        self.active_pids = set()
        self.tempdirs = set()
        self.cleanup_started = False
        self.received_signal = None


_runtime = RuntimeState()
SIGNALS = (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)


def _cleanup():
    """Kill all tracked child processes and remove temp directories."""
    if _runtime.cleanup_started:
        return
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    _runtime.cleanup_started = True
    try:
        for pid in list(_runtime.active_pids):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                # The process exited before cleanup reached it.
                _runtime.active_pids.discard(pid)
                continue
            except OSError as e:
                print(f"cleanup: failed to kill process {pid}: {e}",
                      file=sys.stderr)
                continue
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                # The process was already reaped or is not our child.
                _runtime.active_pids.discard(pid)
                continue
            except OSError as e:
                print(f"cleanup: failed to wait for process {pid}: {e}",
                      file=sys.stderr)
        _runtime.active_pids.clear()

        import shutil
        for d in list(_runtime.tempdirs):
            shutil.rmtree(d, ignore_errors=True)
            if os.path.exists(d):
                print(f"cleanup: failed to remove temporary directory {d}",
                      file=sys.stderr)
        _runtime.tempdirs.clear()
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def tail_file(path, limit=4000):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - limit), os.SEEK_SET)
            data = f.read(limit)
    except OSError:
        return ""
    return data[-limit:].decode(errors="replace")


def load_pycriu():
    """Load generated image bindings before starting a destructive trial."""
    sys.path.insert(0, os.path.join(REPO_ROOT, "lib"))
    try:
        from pycriu import images as pimg
    except (ImportError, OSError) as e:
        raise RuntimeError(
            "pycriu image bindings are unavailable; build them with "
            f"'make -C {REPO_ROOT} lib' before running the benchmark"
        ) from e
    _runtime.pimg = pimg


def _sighandler(signum, frame):
    if _runtime.received_signal is not None:
        return
    _runtime.received_signal = signum
    # subprocess.run() kills and waits for its child while propagating this
    # exception. Destructive cleanup is deferred to atexit after that unwind.
    for handled in SIGNALS:
        signal.signal(handled, signal.SIG_IGN)
    raise SystemExit(128 + signum)


# --- Statistics ---

def median(v):
    s = sorted(v)
    n = len(s)
    if n == 0:
        return 0
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def pct(v, p):
    s = sorted(v)
    n = len(s)
    if n == 0:
        return 0
    k = (n - 1) * p / 100
    f, c = math.floor(k), math.ceil(k)
    return s[f] if f == c else s[f] * (c - k) + s[c] * (k - f)


# --- System info ---

def collect_system_info():
    info = {"kernel": platform.release(), "arch": platform.machine(),
            "cpus": os.cpu_count()}
    try:
        with open("/proc/cpuinfo") as f:
            for ln in f:
                if ln.startswith("model name"):
                    info["cpu"] = ln.split(":", 1)[1].strip()
                    break
    except OSError:
        info["cpu"] = "unknown"
    try:
        with open("/proc/meminfo") as f:
            for ln in f:
                if ln.startswith("MemTotal"):
                    info["memory_mb"] = int(ln.split()[1]) // 1024
                    break
    except OSError:
        info["memory_mb"] = 0
    try:
        r = subprocess.run([_runtime.criu_bin, "--version"],
                           capture_output=True, text=True)
        for ln in r.stdout.strip().split("\n"):
            if ln.startswith("Version"):
                info["criu"] = ln.strip()
                break
    except OSError:
        info["criu"] = "unknown"
    return info


def drop_caches():
    try:
        sync = subprocess.run(["sync"], capture_output=True, text=True)
    except OSError as e:
        raise RuntimeError("failed to execute sync before dropping caches") from e
    if sync.returncode:
        detail = (sync.stderr or sync.stdout).strip()
        raise RuntimeError(
            f"sync failed before dropping caches (rc={sync.returncode}): "
            f"{detail[-1000:]}"
        )
    try:
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("3\n")
    except OSError as e:
        raise RuntimeError(
            "failed to drop host page caches; use --no-drop-caches only "
            "when cache state is intentionally outside the benchmark"
        ) from e


# --- Workload ---

def expected_checksum(pattern, size):
    """SHA-256 of the bytes the workload will write. Computed locally
    by reusing workload.pattern_checksum() so the driver and the workload
    process can never disagree about what 'pattern X' looks like."""
    return workload.pattern_checksum(pattern, size)


def _atomic_write(path, data):
    tmp_path = f"{path}.tmp.{os.getpid()}.{time.monotonic_ns()}"
    try:
        with open(tmp_path, "w") as f:
            f.write(data)
        os.replace(tmp_path, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_path)


def workload_start_timeout(size):
    """Allow startup time to grow with pattern generation and mapping size."""
    scaled_timeout = (size + WORKLOAD_START_MIN_RATE - 1) // \
        WORKLOAD_START_MIN_RATE
    return max(WORKLOAD_START_MIN_TIMEOUT, scaled_timeout)


def start_workload(pattern, size, workdir, expect):
    pp = os.path.join(workdir, "pid")
    ready_path = os.path.join(workdir, "ready")
    request_path = os.path.join(workdir, "checksum-request")
    response_path = os.path.join(workdir, "checksum-response")
    workload_log = os.path.join(workdir, "workload.log")
    with open(workload_log, "wb") as log:
        proc = subprocess.Popen(
            [sys.executable, WORKLOAD_PATH, str(size), pattern, pp, ready_path,
             request_path, response_path],
            stdout=log, stderr=subprocess.STDOUT)
    _runtime.active_pids.add(proc.pid)
    pid = None
    try:
        timeout = workload_start_timeout(size)
        deadline = time.monotonic() + timeout
        for path, stage in ((pp, "PID publication"),
                            (ready_path, "readiness checksum")):
            while not os.path.exists(path):
                if proc.poll() is not None:
                    raise RuntimeError(
                        "workload exited before becoming ready")
                if time.monotonic() > deadline:
                    raise RuntimeError(
                        f"workload initialization timed out after {timeout} "
                        f"seconds while waiting for {stage}")
                time.sleep(0.05)
        with open(pp) as f:
            pid = int(f.read().strip())
        with open(ready_path) as f:
            initial_checksum = f.read().strip()
        if initial_checksum != expect:
            raise RuntimeError(
                "workload initialization checksum mismatch: "
                f"expected {expect}, got {initial_checksum}")
        _runtime.active_pids.add(pid)
        return proc, pid, request_path, response_path
    except Exception:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        proc.wait()
        _runtime.active_pids.discard(proc.pid)
        if pid is not None:
            _runtime.active_pids.discard(pid)
        raise


def restored_checksum(pid, request_path, response_path):
    """Ask the restored workload to checksum its live memory mapping."""
    for path in (request_path, response_path):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)

    token = f"{pid}-{time.monotonic_ns()}"
    _atomic_write(request_path, token + "\n")
    try:
        os.kill(pid, signal.SIGUSR1)
    except ProcessLookupError as e:
        raise RuntimeError("restored workload exited before checksum") from e

    deadline = time.monotonic() + CHECKSUM_TIMEOUT
    while True:
        try:
            with open(response_path) as f:
                response = f.read().strip()
        except FileNotFoundError:
            response = ""

        if response:
            fields = response.split()
            if len(fields) != 2 or fields[0] != token:
                raise RuntimeError(
                    f"invalid restored checksum response: {response!r}")
            digest = fields[1]
            if len(digest) != 64 or any(
                    c not in "0123456789abcdef" for c in digest):
                raise RuntimeError(
                    f"invalid restored checksum digest: {digest!r}")
            return digest

        if time.monotonic() > deadline:
            raise RuntimeError("restored workload checksum timeout")
        time.sleep(0.01)


def stop_workload(pid):
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGTERM)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
    _runtime.active_pids.discard(pid)


# --- Trial ---

def cfg_label(cfg):
    """Short, stable label for a (mode, region_size) pair."""
    if cfg["mode"] == "uncompressed":
        return "Uncompressed"
    if cfg["mode"] == "lz4-page":
        return f"LZ4 per page ({PAGE_SIZE // 1024} KiB blocks)"
    return f"LZ4 regions ({cfg['region_size']//1024} KiB blocks)"


def run_trial(pattern, size, cfg, workdir, expect):
    imgdir = os.path.join(workdir, "img")
    os.makedirs(imgdir)
    if _runtime.drop_caches:
        drop_caches()
    proc, pid, request_path, response_path = start_workload(
        pattern, size, workdir, expect)
    restored = False

    try:
        # Dump
        cmd = [_runtime.criu_bin, "--no-default-config", "dump", "-t", str(pid),
               "-D", imgdir, "--shell-job", "-v0", "-o", "dump.log"]
        mode = cfg["mode"]
        if mode == "lz4-page":
            cmd += ["-c"]
        elif mode == "lz4-region":
            cmd += ["--compress-region", str(cfg["region_size"])]
        if mode != "uncompressed" and _runtime.compress_acceleration != 1:
            cmd += ["--compress-acceleration",
                    str(_runtime.compress_acceleration)]
        t0 = time.monotonic()
        try:
            r = subprocess.run(cmd, capture_output=True)
        except OSError as e:
            raise RuntimeError(f"failed to execute CRIU dump: {e}") from e
        dump_wall = int((time.monotonic() - t0) * 1e6)
        if r.returncode:
            raise RuntimeError(
                f"dump failed (rc={r.returncode}): "
                f"{r.stderr.decode(errors='replace')[-1000:]}"
            )
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                "workload survived the final dump for more than 30 seconds"
            ) from e
        _runtime.active_pids.discard(proc.pid)

        # Measure image
        pages_sz = sum(os.path.getsize(os.path.join(imgdir, f))
                       for f in os.listdir(imgdir)
                       if f.startswith("pages-") and os.path.isfile(os.path.join(imgdir, f)))
        total_sz = sum(os.path.getsize(os.path.join(imgdir, f))
                       for f in os.listdir(imgdir)
                       if os.path.isfile(os.path.join(imgdir, f)))

        # Restore
        restore_cmd = [_runtime.criu_bin, "--no-default-config", "restore", "-D", imgdir,
                       "--shell-job", "-v0", "-o", "restore.log", "-d"]
        restore_cmd += decompress_threads_args(_runtime.decompress_threads)
        t0 = time.monotonic()
        try:
            r = subprocess.run(restore_cmd, capture_output=True)
        except OSError as e:
            raise RuntimeError(f"failed to execute CRIU restore: {e}") from e
        restore_wall = int((time.monotonic() - t0) * 1e6)
        if r.returncode:
            raise RuntimeError(
                f"restore failed (rc={r.returncode}): "
                f"{r.stderr.decode(errors='replace')[-1000:]}"
            )
        restored = True

        with open(os.path.join(workdir, "pid")) as f:
            rpid = int(f.read().strip())
        _runtime.active_pids.add(rpid)
        try:
            # Keep checksum computation outside restore_wall_us: it validates
            # the restored mapping without changing the measured restore
            # boundary.
            valid = restored_checksum(rpid, request_path,
                                      response_path) == expect
        finally:
            stop_workload(rpid)
            restored = False

        # CRIU internal stats
        ds = rs = {}
        for name in ("stats-dump", "stats-restore"):
            p = os.path.join(imgdir, name)
            if os.path.exists(p):
                with open(p, "rb") as f:
                    e = _runtime.pimg.load(f)["entries"][0]
                    if "dump" in e:
                        ds = e["dump"]
                    if "restore" in e:
                        rs = e["restore"]
        required_dump_stats = (
            "pages_written", "frozen_time", "memdump_time", "memwrite_time",
        )
        missing_dump_stats = [name for name in required_dump_stats
                              if name not in ds]
        if missing_dump_stats:
            raise RuntimeError(
                "dump statistics do not contain %s; cannot calculate "
                "benchmark metrics" % ", ".join(missing_dump_stats)
            )
        if "restore_time" not in rs:
            raise RuntimeError(
                "restore statistics do not contain restore_time; cannot "
                "calculate restore throughput"
            )

        logical_pages = (ds["pages_written"] +
                         ds.get("shpages_written", 0))
        if logical_pages <= 0:
            raise RuntimeError(
                "dump statistics report no private or shared pages written"
            )

        return {
            "pages_size": pages_sz, "total_size": total_sz,
            "logical_pages": logical_pages,
            "pages_written": ds["pages_written"],
            "shpages_written": ds.get("shpages_written", 0),
            "frozen_us": ds["frozen_time"],
            "memdump_us": ds["memdump_time"],
            "memwrite_us": ds["memwrite_time"],
            "dump_wall_us": dump_wall,
            "restore_us": rs["restore_time"],
            "restore_wall_us": restore_wall,
            "valid": valid,
        }
    finally:
        if restored:
            # CRIU normally restores the original virtual PID. This fallback
            # covers failures between a successful restore and reading pid.
            stop_workload(pid)
        try:
            proc.kill()
            proc.wait()
        except OSError:
            _runtime.active_pids.discard(proc.pid)
        _runtime.active_pids.discard(proc.pid)


# --- Formatting ---

def format_bytes(byte_count):
    if byte_count >= 1048576:
        return f"{byte_count / 1048576:.1f} MB"
    return f"{byte_count / 1024:.1f} KB"


def format_duration(microseconds):
    if microseconds >= 1e6:
        return f"{microseconds / 1e6:.3f} s"
    return f"{microseconds / 1000:.1f} ms"


def median_throughput(trials, time_key, pages_key="logical_pages"):
    rates = [
        r[pages_key] * PAGE_SIZE / 1048576 / (r[time_key] / 1e6)
        for r in trials if r[pages_key] and r[time_key] > 0
    ]
    return f"{median(rates):.0f} MB/s" if rates else "N/A"


# --- Report ---

def report(name, size_mb, results_by_cfg, cfg_order):
    """results_by_cfg: dict label -> list of trial dicts."""
    label_width = max(24, max(len(label) for label in cfg_order))
    value_width = 12
    W = max(88, label_width + 5 * (value_width + 3) + 5)
    print()
    print("=" * W)
    print(f"  {name.upper()} ({size_mb} MB, n={len(next(iter(results_by_cfg.values())))})")
    print(f"  {PATTERN_DESCRIPTIONS.get(name, 'Workload pattern')}")
    print("=" * W)

    ok = all(r["valid"] for trials in results_by_cfg.values() for r in trials)
    print(f"  Memory integrity: {'PASS' if ok else 'FAIL'}")
    if not ok:
        print("  WARNING: checksum mismatch detected")
    print()

    # Compare page-image bytes per logical byte. This remains meaningful if
    # CRIU writes a slightly different number of pages between trials.
    baseline_label = "Uncompressed" if "Uncompressed" in results_by_cfg else cfg_order[0]
    base_density = median([
        r["pages_size"] / (r["logical_pages"] * PAGE_SIZE)
        for r in results_by_cfg[baseline_label]
        if r["logical_pages"]
    ])
    baseline_note = (
        "CRIU page-image compression disabled"
        if baseline_label == "Uncompressed"
        else "first selected configuration"
    )
    print(f"  Baseline: {baseline_label} ({baseline_note})")

    # Storage
    storage_header = (f"  {'configuration':<{label_width}} | "
                      f"{'pages':>{value_width}} | {'total':>{value_width}} | "
                      f"{'ratio':>{value_width}} | {'saved':>{value_width}}")
    print("  STORAGE (page-image bytes per logical byte, relative to baseline)")
    print(storage_header)
    print("  " + "-" * (len(storage_header) - 2))
    for label in cfg_order:
        trials = results_by_cfg[label]
        ps = median([r["pages_size"] for r in trials])
        ts = median([r["total_size"] for r in trials])
        density = median([
            r["pages_size"] / (r["logical_pages"] * PAGE_SIZE)
            for r in trials if r["logical_pages"]
        ])
        ratio = density / base_density if base_density else 0
        saved = (1 - ratio) if base_density else 0
        print(f"  {label:<{label_width}} | {format_bytes(ps):>{value_width}} | "
              f"{format_bytes(ts):>{value_width}} | {ratio:>{value_width - 1}.3f}x | "
              f"{saved:>{value_width}.0%}")
    print()

    # Latency
    rows = [
        ("Frozen time",     "frozen_us"),
        ("Memory dump",     "memdump_us"),
        ("Page write",      "memwrite_us"),
        ("Dump total",      "dump_wall_us"),
        ("Restore total",   "restore_wall_us"),
    ]
    print("  LATENCY (median)")
    latency_header = (f"  {'configuration':<{label_width}} | "
                      f"{'frozen':>{value_width}} | {'memory dump':>{value_width}} | "
                      f"{'page write':>{value_width}} | {'dump total':>{value_width}} | "
                      f"{'restore total':>{value_width}}")
    print(latency_header)
    print("  " + "-" * (len(latency_header) - 2))
    for lab in cfg_order:
        values = [format_duration(median([r[key] for r in results_by_cfg[lab]]))
                  for _, key in rows]
        print(f"  {lab:<{label_width}} | " + " | ".join(
            f"{value:>{value_width}}" for value in values))
    print()

    # Throughput
    print("  THROUGHPUT (dump uses private pages; restore uses logical pages)")
    throughput_header = (f"  {'configuration':<{label_width}} | "
                         f"{'logical':>{value_width}} | "
                         f"{'dump (write)':>{value_width}} | "
                         f"{'restore':>{value_width}}")
    print(throughput_header)
    print("  " + "-" * (len(throughput_header) - 2))
    for lab in cfg_order:
        trials = results_by_cfg[lab]
        data = median([r["logical_pages"] for r in trials]) * PAGE_SIZE
        dump = median_throughput(trials, "memwrite_us", "pages_written")
        restore = median_throughput(trials, "restore_us")
        print(f"  {lab:<{label_width}} | {format_bytes(data):>{value_width}} | "
              f"{dump:>{value_width}} | {restore:>{value_width}}")

    return ok


# --- Main ---

def main():
    ap = argparse.ArgumentParser(description=__doc__,
         formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", "--iterations", type=int, default=3,
                    help="Measured iterations (default: 3)")
    ap.add_argument("-s", "--size", type=int, default=256,
                    help="Workload memory in MB (default: 256)")
    ap.add_argument("-p", "--data-pattern", nargs="+",
                    default=workload.supported_patterns(),
                    choices=workload.supported_patterns(),
                    help="Data patterns to test (default: all)")
    ap.add_argument("--modes", nargs="+",
                    default=["uncompressed", "lz4-page", "lz4-region"],
                    choices=["uncompressed", "lz4-page", "lz4-region"],
                    help="Compression modes to compare (default: all three)")
    ap.add_argument("--region-sizes", nargs="+", type=int,
                    default=[65536, 262144, 1048576],
                    help="Region sizes (bytes) to sweep when --modes contains "
                         "lz4-region (default: 64K 256K 1M)")
    ap.add_argument("--compress-acceleration", type=int, default=1,
                    help="LZ4 acceleration level (default: 1, higher=faster)")
    ap.add_argument("--decompress-threads", type=int, default=None,
                    help="LZ4/zero-fill worker concurrency "
                         "(default: unset = CRIU default; "
                         "0 = auto; 1 = serial per request; "
                         "N > 1 = aggregate worker limit)")
    ap.add_argument("--criu", default=DEFAULT_CRIU,
                    help="Path to criu (default: %(default)s)")
    ap.add_argument("--json", metavar="FILE",
                    help="Write raw results to JSON")
    ap.add_argument("--no-progress-bar", action="store_true",
                    help="Disable progress bar")
    ap.add_argument("--no-drop-caches", action="store_true",
                    help="Do not drop the host page cache between runs")
    args = ap.parse_args()
    if args.iterations <= 0:
        ap.error("--iterations must be greater than zero")
    if args.size <= 0:
        ap.error("--size must be greater than zero")
    if not 1 <= args.compress_acceleration <= MAX_COMPRESSION_ACCELERATION:
        ap.error("--compress-acceleration must be between 1 and "
                 f"{MAX_COMPRESSION_ACCELERATION}")
    if args.decompress_threads is not None and \
            not 0 <= args.decompress_threads <= MAX_DECOMPRESSION_THREADS:
        ap.error("--decompress-threads must be between 0 and "
                 f"{MAX_DECOMPRESSION_THREADS}")
    if any(size <= 0 or size > MAX_REGION_SIZE or size % PAGE_SIZE
           for size in args.region_sizes):
        ap.error(f"--region-sizes must be positive multiples of {PAGE_SIZE} "
                 f"not exceeding {MAX_REGION_SIZE}")
    if len(args.modes) != len(set(args.modes)):
        ap.error("--modes must not contain duplicate values")
    if len(args.region_sizes) != len(set(args.region_sizes)):
        ap.error("--region-sizes must not contain duplicate values")
    _runtime.criu_bin = args.criu
    _runtime.compress_acceleration = args.compress_acceleration
    _runtime.decompress_threads = args.decompress_threads
    _runtime.drop_caches = not args.no_drop_caches

    if os.getuid() != 0:
        sys.exit("Error: must run as root")
    if not os.access(_runtime.criu_bin, os.X_OK):
        sys.exit(f"Error: {_runtime.criu_bin} not found")
    try:
        load_pycriu()
    except RuntimeError as e:
        sys.exit(f"Error: {e}")

    import atexit
    for handled in SIGNALS:
        signal.signal(handled, _sighandler)
    atexit.register(_cleanup)

    # Build the configuration matrix: each entry is a dict {mode, region_size}.
    cfgs = []
    for m in args.modes:
        if m == "lz4-region":
            for rs in args.region_sizes:
                cfgs.append({"mode": "lz4-region", "region_size": rs})
        else:
            cfgs.append({"mode": m, "region_size": 0})
    cfg_labels = [cfg_label(c) for c in cfgs]

    info = collect_system_info()
    size = args.size * 1024 * 1024
    results = {}

    print()
    print("CRIU Compression Benchmark")
    print(f"  Kernel : {info.get('kernel', '?')}")
    print(f"  CPU    : {info.get('cpu', '?')}")
    print(f"  Memory : {info.get('memory_mb', '?')} MB")
    print(f"  CRIU   : {info.get('criu', '?')}")
    print(f"  Config : {args.size} MB, {args.iterations}+1 iterations, "
          f"modes={','.join(cfg_labels)}")
    print("  Restore: decompress-threads="
          f"{decompress_threads_label(args.decompress_threads)}")

    show_progress = sys.stdout.isatty() and not args.no_progress_bar

    for pat in args.data_pattern:
        exp = expected_checksum(pat, size)
        results_by_cfg = {lab: [] for lab in cfg_labels}
        total = args.iterations + 1

        for i in range(total):
            warmup = (i == 0)
            configurations = list(zip(cfgs, cfg_labels))
            offset = i % len(configurations)
            configurations = configurations[offset:] + configurations[:offset]
            for cfg, lab in configurations:
                wd = tempfile.mkdtemp(prefix="criu-bench-")
                _runtime.tempdirs.add(wd)
                try:
                    r = run_trial(pat, size, cfg, wd, exp)
                    if not r["valid"]:
                        phase = "warmup" if warmup else f"iteration {i}"
                        raise RuntimeError(
                            "memory integrity check failed for "
                            f"{pat} ({lab}, {phase})")
                    if not warmup:
                        results_by_cfg[lab].append(r)
                except Exception as e:
                    # Keep images and logs for post-mortem analysis. Removing
                    # the directory from runtime state also keeps atexit cleanup
                    # from deleting it while the exception unwinds.
                    _runtime.tempdirs.discard(wd)
                    print(f"\n  ERROR: {pat} ({lab}): {e}", file=sys.stderr)
                    print(f"  Artifacts preserved in {wd}", file=sys.stderr)
                    for log_name in ("workload.log", "img/dump.log",
                                     "img/restore.log"):
                        log_tail = tail_file(os.path.join(wd, log_name))
                        if log_tail:
                            print(f"\n  --- {log_name} (tail) ---\n{log_tail}",
                                  file=sys.stderr)
                    raise
                else:
                    import shutil
                    shutil.rmtree(wd)
                    _runtime.tempdirs.discard(wd)
            if show_progress:
                done = i + 1
                bar_w = 20
                filled = bar_w * done // total
                bar = "#" * filled + "." * (bar_w - filled)
                label = "warmup" if warmup else f"{i}/{args.iterations}"
                print(f"\r  {pat}: [{bar}] {label}  ", end="", flush=True)

        if show_progress:
            print(f"\r{' ' * 40}\r", end="")

        if not report(pat, args.size, results_by_cfg, cfg_labels):
            raise RuntimeError(f"memory integrity check failed for {pat}")
        results[pat] = {lab: results_by_cfg[lab] for lab in cfg_labels}

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"system": info,
                       "config": {"iterations": args.iterations,
                                  "size_mb": args.size,
                                  "modes": cfg_labels,
                                  "region_sizes": args.region_sizes,
                                  "compress_acceleration":
                                      args.compress_acceleration,
                                  "decompress_threads":
                                      args.decompress_threads},
                       "results": results}, f, indent=2)
        print(f"\nResults written to {args.json}")

    print()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as e:
        sys.exit(f"Error: {e}")
