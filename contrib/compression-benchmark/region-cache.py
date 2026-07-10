#!/usr/bin/env python3
"""
Benchmark repeated partial reads from region-compressed parent images.

The workload intentionally modifies every other page after a compressed
pre-dump. On restore, the final image reads alternating pages from the
compressed parent image, which exercises repeated partial reads from the
same region-compressed block.
"""

import argparse
import atexit
import contextlib
import hashlib
import json
import math
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
MAX_REGION_SIZE = 4 * 1024 * 1024
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
DEFAULT_CRIU = os.path.join(REPO_ROOT, "criu", "criu")
PE_PARENT = 1 << 0
PE_PRESENT = 1 << 2

class RuntimeState:
    """Mutable process state shared by signal and cleanup handlers."""

    def __init__(self):
        self.active_pids = set()
        self.cleanup_started = False
        self.received_signal = None
        self.pimg = None


_runtime = RuntimeState()
SIGNALS = (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)


class TrialError(Exception):
    def __init__(self, message, details=None):
        super().__init__(message)
        self.details = details or {}


def parse_size(value):
    value = str(value).strip()
    if not value:
        raise argparse.ArgumentTypeError("empty size")
    mult = 1
    if value[-1] in ("K", "k"):
        mult = 1024
        value = value[:-1]
    elif value[-1] in ("M", "m"):
        mult = 1024 * 1024
        value = value[:-1]
    elif value[-1] in ("G", "g"):
        mult = 1024 * 1024 * 1024
        value = value[:-1]
    try:
        size = int(value) * mult
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))
    if size <= 0 or size % PAGE_SIZE:
        raise argparse.ArgumentTypeError("size must be a positive page multiple")
    return size


def fmt_size(size):
    for suffix, unit in (("G", 1024 ** 3), ("M", 1024 ** 2), ("K", 1024)):
        if size % unit == 0:
            return f"{size // unit}{suffix}"
    return str(size)


def median(values):
    values = sorted(values)
    if not values:
        return None
    n = len(values)
    if n % 2:
        return values[n // 2]
    return (values[n // 2 - 1] + values[n // 2]) / 2


def percentile(values, pct):
    values = sorted(values)
    if not values:
        return None
    k = (len(values) - 1) * pct / 100
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return values[lo]
    return values[lo] * (hi - k) + values[hi] * (k - lo)


def fmt_sec(value):
    if value is None:
        return "n/a"
    return f"{value:.3f}s"


def load_pycriu():
    sys.path.insert(0, os.path.join(REPO_ROOT, "lib"))
    try:
        from pycriu import images as pimg
    except (ImportError, OSError) as exc:
        raise RuntimeError(
            "pycriu image bindings are unavailable; build them with "
            f"'make -C {REPO_ROOT} lib' before running the benchmark"
        ) from exc
    _runtime.pimg = pimg


def _pagemap_flags(entry):
    has_flags = "flags" in entry
    flags = entry.get("flags", 0)
    if entry.get("in_parent"):
        flags |= PE_PARENT
    elif not has_flags:
        flags = PE_PRESENT
    return flags


def _pagemap_pages(entry):
    pages = entry.get("nr_pages", entry.get("compat_nr_pages"))
    if not isinstance(pages, int) or pages <= 0:
        raise TrialError("pagemap entry has an invalid page count")
    return pages


def load_pagemap_entries(directory, pid):
    path = os.path.join(directory, f"pagemap-{pid}.img")
    try:
        with open(path, "rb") as image_file:
            image = _runtime.pimg.load(image_file)
    except (OSError, ValueError) as exc:
        raise TrialError(f"unable to read {path}: {exc}") from exc
    entries = image.get("entries", [])
    if not entries:
        raise TrialError(f"pagemap image has no header: {path}")
    return entries[1:]


def analyze_partial_region_reads(pre_entries, final_entries, mapping_start,
                                 size, region_size):
    page_count = size // PAGE_SIZE
    region_pages = region_size // PAGE_SIZE
    mapping_end = mapping_start + size
    pre_coverage = bytearray(page_count)
    lz4_blocks = []

    for entry in pre_entries:
        entry_start = entry["vaddr"]
        entry_pages = _pagemap_pages(entry)
        entry_end = entry_start + entry_pages * PAGE_SIZE
        overlap_start = max(entry_start, mapping_start)
        overlap_end = min(entry_end, mapping_end)
        if overlap_start >= overlap_end:
            continue
        if not _pagemap_flags(entry) & PE_PRESENT:
            raise TrialError("pre-dump does not contain the workload pages")
        if entry.get("region_pages") != region_pages:
            raise TrialError("pre-dump does not use the requested region size")

        compressed_sizes = entry.get("compressed_size", [])
        expected_blocks = (entry_pages + region_pages - 1) // region_pages
        if len(compressed_sizes) != expected_blocks:
            raise TrialError("pre-dump has incomplete region metadata")

        first_page = (overlap_start - mapping_start) // PAGE_SIZE
        last_page = (overlap_end - mapping_start) // PAGE_SIZE
        pre_coverage[first_page:last_page] = b"\1" * (last_page - first_page)

        block_start = entry_start
        pages_left = entry_pages
        for compressed_size in compressed_sizes:
            block_pages = min(region_pages, pages_left)
            block_end = block_start + block_pages * PAGE_SIZE
            if (block_end > mapping_start and block_start < mapping_end and
                    0 < compressed_size < block_pages * PAGE_SIZE):
                lz4_blocks.append((block_start, block_end))
            block_start = block_end
            pages_left -= block_pages

    if not all(pre_coverage):
        raise TrialError("pre-dump does not cover the complete workload mapping")
    if not lz4_blocks:
        raise TrialError("pre-dump workload has no LZ4-compressed region")

    final_storage = bytearray(page_count)
    parent_extents = []
    for entry in final_entries:
        entry_start = entry["vaddr"]
        entry_end = entry_start + _pagemap_pages(entry) * PAGE_SIZE
        overlap_start = max(entry_start, mapping_start)
        overlap_end = min(entry_end, mapping_end)
        if overlap_start >= overlap_end:
            continue

        flags = _pagemap_flags(entry)
        is_parent = bool(flags & PE_PARENT)
        is_present = bool(flags & PE_PRESENT)
        if is_parent == is_present:
            raise TrialError("final dump has invalid workload page storage")
        storage = 2 if is_parent else 1
        first_page = (overlap_start - mapping_start) // PAGE_SIZE
        last_page = (overlap_end - mapping_start) // PAGE_SIZE
        if any(final_storage[first_page:last_page]):
            raise TrialError("final dump has overlapping workload entries")
        final_storage[first_page:last_page] = bytes([storage]) * (last_page - first_page)
        if is_parent:
            parent_extents.append((overlap_start, overlap_end))

    for page_index, storage in enumerate(final_storage):
        expected_storage = 1 if page_index % 2 == 0 else 2
        if storage != expected_storage:
            raise TrialError(
                "final dump does not alternate present and parent pages")

    slices_by_block = [0] * len(lz4_blocks)
    partial_parent_slices = 0
    for extent_start, extent_end in parent_extents:
        for block_index, (block_start, block_end) in enumerate(lz4_blocks):
            overlap_start = max(extent_start, block_start, mapping_start)
            overlap_end = min(extent_end, block_end, mapping_end)
            if overlap_start >= overlap_end:
                continue
            target_start = max(block_start, mapping_start)
            target_end = min(block_end, mapping_end)
            if overlap_start == target_start and overlap_end == target_end:
                continue
            partial_parent_slices += 1
            slices_by_block[block_index] += 1

    reused_regions = sum(count >= 2 for count in slices_by_block)
    if not reused_regions:
        raise TrialError(
            "workload does not make repeated partial reads from an LZ4 region")
    return {
        "partial_parent_slices": partial_parent_slices,
        "reused_lz4_regions": reused_regions,
        "max_slices_per_region": max(slices_by_block),
    }


def validate_region_cache_images(pre_dir, dump_dir, pid, mapping_start,
                                 size, region_size):
    pre_entries = load_pagemap_entries(pre_dir, pid)
    final_entries = load_pagemap_entries(dump_dir, pid)
    return analyze_partial_region_reads(
        pre_entries, final_entries, mapping_start, size, region_size)


def page_bytes(kind, index):
    fill = b"A" if kind == "base" else b"B"
    page = bytearray(fill * PAGE_SIZE)
    token = f"{kind}:{index:016x}".encode()
    page[:len(token)] = token
    return page


def expected_checksum(size):
    pages = size // PAGE_SIZE
    h = hashlib.sha256()
    for index in range(pages):
        kind = "dirty" if index % 2 == 0 else "base"
        h.update(page_bytes(kind, index))
    return h.hexdigest()


def fill_mapping(mapping, size, kind, stride):
    pages = size // PAGE_SIZE
    for index in range(0, pages, stride):
        off = index * PAGE_SIZE
        mapping[off:off + PAGE_SIZE] = page_bytes(kind, index)


def checksum_mapping(mapping, size):
    h = hashlib.sha256()
    view = memoryview(mapping)
    chunk = 1024 * 1024
    for off in range(0, size, chunk):
        h.update(view[off:off + min(chunk, size - off)])
    return h.hexdigest()


def atomic_write_text(path, data):
    """Publish a complete marker without exposing a partially written file."""
    tmp_path = f"{path}.tmp.{os.getpid()}.{time.monotonic_ns()}"
    try:
        with open(tmp_path, "w") as output:
            output.write(data)
        os.replace(tmp_path, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_path)


def workload_child(argv):
    import ctypes
    import mmap

    size = int(argv[0])
    ready_path = argv[1]
    dirty_path = argv[2]
    checksum_path = argv[3]
    wait_signals = {signal.SIGUSR1, signal.SIGUSR2, signal.SIGTERM}
    signal.pthread_sigmask(signal.SIG_BLOCK, wait_signals)

    mapping = mmap.mmap(-1, size, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                mmap.PROT_READ | mmap.PROT_WRITE)
    fill_mapping(mapping, size, "base", 1)
    mapping_start = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
    atomic_write_text(ready_path, f"{os.getpid()} {mapping_start}\n")

    while True:
        # Blocking the signals before publishing readiness closes the race in
        # which a signal arrived after a state check but before signal.pause().
        signum = signal.sigwait(wait_signals)
        if signum == signal.SIGTERM:
            break
        if signum == signal.SIGUSR1:
            fill_mapping(mapping, size, "dirty", 2)
            atomic_write_text(dirty_path, "done\n")
        elif signum == signal.SIGUSR2:
            atomic_write_text(
                checksum_path, checksum_mapping(mapping, size) + "\n")
    return 0


def cleanup_pids():
    if _runtime.cleanup_started:
        return
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    _runtime.cleanup_started = True
    try:
        for pid in list(_runtime.active_pids):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The process exited before cleanup reached it.
            except OSError as exc:
                print(f"cleanup: failed to kill process {pid}: {exc}",
                      file=sys.stderr)
                _runtime.active_pids.discard(pid)
                continue
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass  # Restored processes are not children, or were reaped.
            except OSError as exc:
                print(f"cleanup: failed to wait for process {pid}: {exc}",
                      file=sys.stderr)
            _runtime.active_pids.discard(pid)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def on_signal(signum, _frame):
    if _runtime.received_signal is not None:
        return
    _runtime.received_signal = signum
    for handled in SIGNALS:
        signal.signal(handled, signal.SIG_IGN)
    raise SystemExit(128 + signum)


def wait_for_path(path, timeout=60, proc=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        if proc is not None:
            returncode = proc.poll()
            if returncode is not None:
                raise TrialError(
                    f"workload exited with status {returncode} while waiting "
                    f"for {path}"
                )
        time.sleep(0.05)
    raise TrialError(f"timeout waiting for {path}")


def tail_file(path, limit=4000):
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - limit), os.SEEK_SET)
            data = handle.read(limit)
    except OSError:
        return ""
    return data[-limit:].decode(errors="replace")


def run_cmd(cmd, cwd=None):
    start = time.monotonic()
    proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE)
    elapsed = time.monotonic() - start
    if proc.returncode:
        raise TrialError(
            f"command failed: {' '.join(cmd)}",
            {
                "returncode": proc.returncode,
                "stdout": proc.stdout.decode(errors="replace")[-4000:],
                "stderr": proc.stderr.decode(errors="replace")[-4000:],
            },
        )
    return elapsed


def criu_version(criu):
    try:
        proc = subprocess.run([criu, "--version"], stdout=subprocess.PIPE,
                      stderr=subprocess.PIPE, text=True)
    except OSError as exc:
        return f"unavailable: {exc}"
    if proc.returncode:
        return proc.stderr.strip() or f"exit {proc.returncode}"
    return " ".join(line.strip() for line in proc.stdout.splitlines() if line.strip())


def start_workload(size, workdir):
    ready = os.path.join(workdir, "ready")
    dirty = os.path.join(workdir, "dirty")
    checksum = os.path.join(workdir, "checksum")
    log = os.path.join(workdir, "workload.log")
    with open(log, "wb") as out:
        proc = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__),
             "--workload-child", str(size), ready, dirty, checksum],
            cwd=workdir, stdout=out, stderr=subprocess.STDOUT)
    _runtime.active_pids.add(proc.pid)
    try:
        wait_for_path(ready, proc=proc)
        with open(ready) as handle:
            pid_text, mapping_start_text = handle.read().split()
        pid = int(pid_text)
        mapping_start = int(mapping_start_text)
        if pid != proc.pid:
            raise TrialError(
                f"workload published PID {pid}, expected {proc.pid}"
            )
        return proc, pid, mapping_start, dirty, checksum
    except BaseException:
        if proc.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
        proc.wait()
        _runtime.active_pids.discard(proc.pid)
        raise


def signal_and_wait(pid, signum, path, timeout=120):
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
    os.kill(pid, signum)
    wait_for_path(path, timeout)


def run_trial(criu, size, region_size, expected, root, keep_workdirs):
    workdir = tempfile.mkdtemp(prefix="region-cache-", dir=root)
    pre_dir = os.path.join(workdir, "img", "pre")
    dump_dir = os.path.join(workdir, "img", "dump")
    proc = None
    pid = None
    restored_pid = None
    failed = False
    try:
        os.makedirs(pre_dir)
        os.makedirs(dump_dir)
        proc, pid, mapping_start, dirty_path, checksum_path = start_workload(
            size, workdir)

        pre_cmd = [
            criu, "--no-default-config", "pre-dump", "-t", str(pid), "-D", pre_dir,
            "-o", "pre-dump.log", "-v4", "--shell-job",
            "--track-mem", "-R", "--compress-region",
            str(region_size),
        ]
        pre_dump_s = run_cmd(pre_cmd)

        signal_and_wait(pid, signal.SIGUSR1, dirty_path)

        dump_cmd = [
            criu, "--no-default-config", "dump", "-t", str(pid), "-D", dump_dir,
            "-o", "dump.log", "-v4", "--shell-job",
            "--prev-images-dir=../pre", "--track-mem",
            "--compress-region", str(region_size),
        ]
        dump_s = run_cmd(dump_cmd)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            raise TrialError("workload survived final dump")
        _runtime.active_pids.discard(proc.pid)

        cache_evidence = validate_region_cache_images(
            pre_dir, dump_dir, pid, mapping_start, size, region_size)
        pid = None

        restore_pidfile = os.path.join(workdir, "restore.pid")
        restore_cmd = [
            criu, "--no-default-config", "restore", "-D", dump_dir, "-o", "restore.log",
            "-v4", "--shell-job", "-d", "--pidfile",
            restore_pidfile,
        ]
        restore_s = run_cmd(restore_cmd)
        wait_for_path(restore_pidfile)
        with open(restore_pidfile) as handle:
            restored_pid = int(handle.read().strip())
        _runtime.active_pids.add(restored_pid)

        signal_and_wait(restored_pid, signal.SIGUSR2, checksum_path)
        with open(checksum_path) as handle:
            got = handle.read().strip()
        if got != expected:
            raise TrialError("restored checksum mismatch",
                     {"expected": expected, "got": got})

        with contextlib.suppress(ProcessLookupError):
            os.kill(restored_pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(restored_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            with contextlib.suppress(ProcessLookupError):
                os.kill(restored_pid, signal.SIGKILL)
        _runtime.active_pids.discard(restored_pid)
        restored_pid = None

        return {
            "ok": True,
            "workdir": workdir if keep_workdirs else None,
            "pre_dump_s": pre_dump_s,
            "dump_s": dump_s,
            "restore_s": restore_s,
            "total_s": pre_dump_s + dump_s + restore_s,
            "cache_evidence": cache_evidence,
        }
    except TrialError as exc:
        failed = True
        details = dict(exc.details)
        details.update({
            "pre_dump_log": tail_file(os.path.join(pre_dir, "pre-dump.log")),
            "dump_log": tail_file(os.path.join(dump_dir, "dump.log")),
            "restore_log": tail_file(os.path.join(dump_dir, "restore.log")),
            "workload_log": tail_file(os.path.join(workdir, "workload.log")),
        })
        return {
            "ok": False,
            "workdir": workdir,
            "error": str(exc),
            "details": details,
        }
    except Exception as exc:
        failed = True
        return {
            "ok": False,
            "workdir": workdir,
            "error": f"unexpected trial failure: {exc}",
            "details": {
                "pre_dump_log": tail_file(os.path.join(pre_dir, "pre-dump.log")),
                "dump_log": tail_file(os.path.join(dump_dir, "dump.log")),
                "restore_log": tail_file(os.path.join(dump_dir, "restore.log")),
                "workload_log": tail_file(os.path.join(workdir, "workload.log")),
            },
        }
    finally:
        if restored_pid is not None:
            try:
                os.kill(restored_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The restored workload already exited.
            except OSError as exc:
                print(f"cleanup: failed to kill restored process "
                      f"{restored_pid}: {exc}", file=sys.stderr)
            _runtime.active_pids.discard(restored_pid)
        if pid is not None:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
            _runtime.active_pids.discard(pid)
        if proc is not None:
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        if not keep_workdirs and not failed:
            shutil.rmtree(workdir, ignore_errors=True)


def collect_system_info():
    info = {
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpus": os.cpu_count(),
    }
    with contextlib.suppress(OSError):
        with open("/proc/cpuinfo") as handle:
            for line in handle:
                if line.startswith("model name"):
                    info["cpu"] = line.split(":", 1)[1].strip()
                    break
    return info


def summarize_trials(trials):
    restore = [t["restore_s"] for t in trials if t.get("ok") and not t.get("warmup")]
    return {
        "count": len(restore),
        "restore_median_s": median(restore),
        "restore_p25_s": percentile(restore, 25),
        "restore_p75_s": percentile(restore, 75),
        "restore_values_s": restore,
        "failures": [t for t in trials if not t.get("ok")],
    }


def write_results(path, data):
    json_path = path + ".json"
    with open(json_path, "w") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)

    without_cache = data["summary"]["without_cache"]
    cached = data["summary"]["cached"]
    base_med = without_cache["restore_median_s"]
    cached_med = cached["restore_median_s"]
    speedup = None
    if base_med and cached_med:
        speedup = (base_med / cached_med - 1) * 100

    lines = [
        "# Region-compressed parent restore benchmark",
        "",
        f"Workload: {data['config']['size']} anonymous mapping, every other page modified after pre-dump.",
        f"Region size: {data['config']['region_size']}",
        f"Iterations: {data['config']['iterations']} measured, {data['config']['warmups']} warmup",
        f"Kernel: {data['system'].get('kernel', 'unknown')} ({data['system'].get('arch', 'unknown')})",
        f"CPU: {data['system'].get('cpu', 'unknown')}",
        "",
        "| configuration | CRIU | median restore | p25..p75 | successful runs |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for label, display in (("without_cache", "Without cache"), ("cached", "Cached")):
        summary = data["summary"][label]
        version = data["criu"][label]["version"].replace("|", "\\|")
        lines.append(
            f"| {display} | `{version}` | {fmt_sec(summary['restore_median_s'])} | "
            f"{fmt_sec(summary['restore_p25_s'])}..{fmt_sec(summary['restore_p75_s'])} | "
            f"{summary['count']} |"
        )
    lines += ["", "Baseline: CRIU without region cache", "Cached: CRIU with region cache"]
    lines += ["", "Restore speedup: " + (f"{speedup:.1f}%" if speedup is not None else "n/a")]
    lines += ["", "Measured restore times:"]
    for label, display in (("without_cache", "without cache"), ("cached", "cached")):
        values = ", ".join(fmt_sec(v) for v in data["summary"][label]["restore_values_s"])
        lines.append(f"- {display}: {values or 'none'}")
    lines += ["", "Commands:"]
    lines.append(
        "```sh\n"
        f"python3 contrib/compression-benchmark/region-cache.py "
        f"--without-cache-criu {data['criu']['without_cache']['path']} "
        f"--cached-criu {data['criu']['cached']['path']} "
        f"--iterations {data['config']['iterations']} "
        f"--warmups {data['config']['warmups']} "
        f"--size {data['config']['size']} "
        f"--region-size {data['config']['region_size']} "
        f"--output {path}\n"
        "```"
    )
    failures = without_cache["failures"] + cached["failures"]
    if failures:
        lines += ["", "Failures:"]
        for failure in failures:
            lines.append(
                f"- {failure.get('label', 'unknown')}: "
                f"{failure.get('error', 'unknown error')} "
                f"(artifacts: `{failure.get('workdir', 'unknown')}`)"
            )
    with open(path, "w") as handle:
        handle.write("\n".join(lines))
        handle.write("\n")
    return json_path


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--without-cache-criu", required=True,
                help="CRIU binary without the region cache")
    parser.add_argument("--cached-criu", default=DEFAULT_CRIU,
                help="CRIU binary with the region cache")
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--size", type=parse_size, default=parse_size("512M"))
    parser.add_argument("--region-size", type=parse_size,
                default=parse_size("1M"))
    parser.add_argument("--output", default="region-cache-results.md")
    parser.add_argument("--tmpdir", default=None)
    parser.add_argument("--keep-workdirs", action="store_true")
    args = parser.parse_args(argv)

    if args.iterations <= 0 or args.warmups < 0:
        parser.error("iterations must be > 0 and warmups must be >= 0")
    if args.region_size > MAX_REGION_SIZE:
        parser.error(f"--region-size must not exceed {MAX_REGION_SIZE}")

    try:
        load_pycriu()
    except RuntimeError as exc:
        parser.error(str(exc))

    without_cache_criu = os.path.abspath(args.without_cache_criu)
    cached_criu = os.path.abspath(args.cached_criu)

    data = {
        "system": collect_system_info(),
        "config": {
            "iterations": args.iterations,
            "warmups": args.warmups,
            "size": fmt_size(args.size),
            "size_bytes": args.size,
            "region_size": fmt_size(args.region_size),
            "region_size_bytes": args.region_size,
        },
        "criu": {
            "without_cache": {
                "path": without_cache_criu,
                "version": criu_version(without_cache_criu),
            },
            "cached": {
                "path": cached_criu,
                "version": criu_version(cached_criu),
            },
        },
        "trials": {"without_cache": [], "cached": []},
    }

    root = args.tmpdir or tempfile.gettempdir()
    # This is O(mapping size), so compute it once rather than adding the same
    # CPU and memory-bandwidth load after every timed restore.
    expected = expected_checksum(args.size)
    total = args.warmups + args.iterations
    for index in range(total):
        configurations = [
            ("without_cache", without_cache_criu),
            ("cached", cached_criu),
        ]
        # Alternate A/B and B/A ordering to reduce drift from cache warming,
        # CPU frequency, and other time-correlated host effects.
        if index % 2:
            configurations.reverse()
        for order, (label, criu) in enumerate(configurations):
            print(f"{label} iteration {index + 1}/{total}", flush=True)
            trial = run_trial(criu, args.size, args.region_size, expected, root,
                      args.keep_workdirs)
            trial["label"] = label
            trial["iteration"] = index
            trial["order"] = order
            trial["warmup"] = index < args.warmups
            data["trials"][label].append(trial)
            if not trial.get("ok"):
                print(f"{label} failed: {trial.get('error', 'unknown error')}",
                      file=sys.stderr)
                print(f"artifacts preserved in {trial['workdir']}",
                      file=sys.stderr)

    data["summary"] = {
        "without_cache": summarize_trials(data["trials"]["without_cache"]),
        "cached": summarize_trials(data["trials"]["cached"]),
    }
    json_path = write_results(args.output, data)
    print(f"Wrote {args.output}")
    print(f"Wrote {json_path}")

    failures = data["summary"]["without_cache"]["failures"] + data["summary"]["cached"]["failures"]
    return 1 if failures else 0


if __name__ == "__main__":
    atexit.register(cleanup_pids)
    for handled in SIGNALS:
        signal.signal(handled, on_signal)
    if len(sys.argv) > 1 and sys.argv[1] == "--workload-child":
        raise SystemExit(workload_child(sys.argv[2:]))
    raise SystemExit(main(sys.argv[1:]))
