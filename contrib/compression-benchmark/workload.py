#!/usr/bin/env python3
"""
Workload that the compression benchmark dumps and restores.

Provides helpers used by both the long-running workload process (this file's
__main__ block) and the benchmark driver (main.py) to fill memory and compute
expected checksums without re-implementing the generators.

Patterns:
  zero    - all pages zero
  mixed   - 50% zero, 25% repeating, 25% random
  random  - pseudorandom (seed = 42), incompressible
  text    - JSON-shaped records with repeated keys
  elf     - concatenated system binaries
"""

import hashlib
import mmap
import os
import random
import signal
import sys

CHUNK_SIZE = 1024 * 1024


def _random_bytes(rng, size):
    return rng.getrandbits(size * 8).to_bytes(size, "little")


def _iter_randbytes(rng, size, chunk_size=CHUNK_SIZE):
    remaining = size
    while remaining:
        n = min(remaining, chunk_size)
        yield _random_bytes(rng, n)
        remaining -= n


def _repeat_to_size(data, size):
    if not data:
        return
    full, tail = divmod(size, len(data))
    for _ in range(full):
        yield data
    if tail:
        yield data[:tail]


def _gen_zero(size):
    return b"".join(_iter_zero(size))


def _gen_random(size):
    return b"".join(_iter_random(size))


def _gen_mixed(size):
    return b"".join(_iter_mixed(size))


def _iter_zero(size):
    for chunk in _repeat_to_size(bytes(CHUNK_SIZE), size):
        yield chunk


def _iter_random(size):
    rng = random.Random(42)
    yield from _iter_randbytes(rng, size)


def _iter_mixed(size):
    rng = random.Random(42)
    half = size // 2
    quarter = size // 4
    yield from _iter_zero(half)                         # zero half
    yield from _repeat_to_size(b"CRIU" * 1024, quarter) # repeating quarter
    yield from _iter_randbytes(rng, size - half - quarter) # random tail


def _gen_text(size):
    """JSON-like records with repeated keys; LZ4 finds long matches once
    the dictionary warms up. Pre-generates a value pool so we stay fast
    at large sizes."""
    rng = random.Random(42)
    keys = [b"id", b"name", b"created_at", b"status", b"score",
            b"description", b"owner", b"tags"]
    pool = [bytes(c % 75 + 48 for c in _random_bytes(rng, 16))
            for _ in range(4096)]

    buf = bytearray()
    pi = 0
    while len(buf) < size:
        rec = b"{"
        for k in keys:
            rec += b'"' + k + b'":"' + pool[pi & 4095] + b'",'
            pi += 1
        rec = rec[:-1] + b"}\n"
        buf += rec
    return bytes(buf[:size])


def _iter_text(size):
    rng = random.Random(42)
    keys = [b"id", b"name", b"created_at", b"status", b"score",
            b"description", b"owner", b"tags"]
    pool = [bytes(c % 75 + 48 for c in _random_bytes(rng, 16))
            for _ in range(4096)]

    buf = bytearray()
    pi = 0
    while len(buf) < size:
        while len(buf) < CHUNK_SIZE and len(buf) < size:
            rec = b"{"
            for k in keys:
                rec += b'"' + k + b'":"' + pool[pi & 4095] + b'",'
                pi += 1
            rec = rec[:-1] + b"}\n"
            buf += rec
        out = bytes(buf[:min(len(buf), size)])
        yield out
        size -= len(out)
        del buf[:len(out)]


def _read_elf_sources():
    chunks = []
    skipped = []
    paths = ["/bin/bash", "/usr/bin/python3", "/bin/cp", "/bin/tar",
             "/usr/bin/grep", "/usr/bin/awk", "/usr/bin/ls"]
    for p in paths:
        try:
            with open(p, "rb") as f:
                data = f.read()
        except OSError as e:
            # Binary locations vary by distribution. Report unavailable
            # candidates while still using every readable ELF input.
            skipped.append(f"{p}: {e.strerror or e}")
            continue
        if data:
            chunks.append(data)
        else:
            skipped.append(f"{p}: empty file")
    if skipped:
        print("workload: skipped ELF inputs: " + "; ".join(skipped),
              file=sys.stderr)
    if not chunks:
        raise RuntimeError("ELF pattern has no readable system binaries")
    return chunks


def _gen_elf(size):
    """Concatenated system binaries with code and string-table pages."""
    chunks = _read_elf_sources()
    out = bytearray()
    i = 0
    while len(out) < size:
        out += chunks[i % len(chunks)]
        i += 1
    return bytes(out[:size])


def _iter_elf(size):
    chunks = _read_elf_sources()

    i = 0
    buf = bytearray()
    while size:
        while len(buf) < CHUNK_SIZE and size:
            chunk = chunks[i % len(chunks)]
            take = min(len(chunk), size)
            buf += chunk[:take]
            size -= take
            i += 1
        yield bytes(buf)
        buf.clear()


_GENERATORS = {
    "zero":   _gen_zero,
    "mixed":  _gen_mixed,
    "random": _gen_random,
    "text":   _gen_text,
    "elf":    _gen_elf,
}

_ITERATORS = {
    "zero":   _iter_zero,
    "mixed":  _iter_mixed,
    "random": _iter_random,
    "text":   _iter_text,
    "elf":    _iter_elf,
}


def supported_patterns():
    return list(_GENERATORS)


def fill_pattern(pattern, size):
    """Return `size` bytes of the named pattern. Used both as the source
    of truth in the workload process and by the driver's expected
    checksum routine."""
    if pattern not in _GENERATORS:
        raise ValueError(f"unknown pattern {pattern!r}")
    return _GENERATORS[pattern](size)


def iter_pattern(pattern, size):
    """Yield the named pattern in bounded chunks."""
    if pattern not in _ITERATORS:
        raise ValueError(f"unknown pattern {pattern!r}")
    yield from _ITERATORS[pattern](size)


def pattern_checksum(pattern, size):
    h = hashlib.sha256()
    for chunk in iter_pattern(pattern, size):
        h.update(chunk)
    return h.hexdigest()


def mapping_checksum(mapping):
    """Return the SHA-256 of the bytes currently stored in *mapping*."""
    return hashlib.sha256(mapping).hexdigest()


def atomic_write(path, data):
    """Publish a complete response without exposing a partial file."""
    tmp_path = f"{path}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "w") as f:
            f.write(data)
        os.replace(tmp_path, path)
    finally:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass  # os.replace() already moved a successfully published file.


def _main():
    # argv: workload.py SIZE PATTERN PID_PATH READY_PATH REQUEST_PATH RESPONSE_PATH
    size = int(sys.argv[1])
    pattern = sys.argv[2]
    pid_path = sys.argv[3]
    ready_path = sys.argv[4]
    request_path = sys.argv[5]
    response_path = sys.argv[6]

    wait_signals = {signal.SIGUSR1, signal.SIGTERM}
    signal.pthread_sigmask(signal.SIG_BLOCK, wait_signals)

    m = mmap.mmap(-1, size, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                  mmap.PROT_READ | mmap.PROT_WRITE)
    offset = 0
    for chunk in iter_pattern(pattern, size):
        m[offset:offset + len(chunk)] = chunk
        offset += len(chunk)

    atomic_write(pid_path, str(os.getpid()))
    atomic_write(ready_path, mapping_checksum(m))

    while True:
        signo = signal.sigwait(wait_signals)
        if signo == signal.SIGTERM:
            break

        try:
            with open(request_path) as f:
                token = f.read().strip()
        except OSError:
            # A request is published before SIGUSR1 is sent. If it is
            # missing, leave no response that the driver could mistake for
            # a successful integrity check.
            continue

        if not token:
            continue

        digest = mapping_checksum(m)
        atomic_write(response_path, f"{token} {digest}\n")


if __name__ == "__main__":
    _main()
