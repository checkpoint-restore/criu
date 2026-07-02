# CLONE Dump: Phased Live Migration

CLONE dump is an experimental CRIU mode that minimizes source-process downtime during live migration. It leverages Linux's userfaultfd write-protect (`UFFD_FEATURE_WP_ASYNC`) and `PAGEMAP_SCAN` to let the process continue running while pages stream to the target, reducing freeze time to two brief windows.

For the full design specification, see the [detailed design document](https://asafpamzn.github.io/criu/clone-dump-design.html).

## Goals

1. **Reduce source downtime** — Only two short freezes; source stays responsive throughout migration
2. **Minimize total migration time** — Wall-clock dominated by physical resources (network/CPU), not design limitations
3. **No disk required** — Pages stream directly from source memory to target memory; no intermediate image files for pages

## How It Differs from Existing Approaches

CRIU already supports two techniques for reducing migration downtime:

**Pre-dump / Iterative Migration** (see [memory-changes-tracking.md](memory-changes-tracking.md)):
- Multiple passes transfer dirty pages while process runs
- Final dump still freezes process for full state capture
- Requires disk I/O for intermediate images

**Lazy Pages** (see [userfaultfd.md](userfaultfd.md)):
- Process resumes immediately with empty memory regions
- Pages fetched on-demand when accessed
- Application experiences latency spikes during page faults

**CLONE dump** combines the best of both:
- Process runs during transfer (like pre-dump)
- No disk I/O — direct memory-to-memory streaming
- Pages pre-buffered on target before restore (no on-demand latency)
- Only two brief freezes: initial WP setup and final state capture

## Architecture Overview

Source and target communicate via a fan of parallel TCP sockets carrying LZ4-compressed page batches. The migration proceeds through four phases.

### Phase 1: Seize + WP_ASYNC Initialization

**Source:**
- Briefly freezes the process
- Registers all writable VMAs with userfaultfd in async write-protect mode
- Applies write-protect in parallel across address space
- Unfreezes process immediately
- Subsequent page writes leave a soft-dirty trail exposed via `PAGEMAP_SCAN`

**Target:**
- Waits for per-thread page-transfer connections

### Phase 2a: Bulk Transfer

**Source:**
- Process continues running
- Pool of bulk-sender threads reads chunks via `process_vm_readv`
- Compresses with LZ4 and writes to per-thread TCP sockets
- Thread count controlled by `--clone-p3-threads-bulk`

**Target:**
- Matching receiver threads decompress each batch
- Pages stored in in-memory buffer keyed by virtual address
- Nothing applied to target process yet — pages only accumulate

### Phase 2b: Pre-Scan Convergence (Optional)

Enabled with `--clone-pre-scan` flag.

**Source:**
- Scanner threads query kernel for dirty pages via `PAGEMAP_SCAN`
- Publishes dirty regions to lock-free MPMC queue
- Sender threads drain queue and ship dirty pages
- Loops until dirty count below convergence threshold

**Target:**
- Receivers detect re-sent regions already in buffer
- Decompress directly on top of older copy (in-place overwrite)

### Phase 3: Freeze + Skeleton Dump

This is the critical downtime window.

**Source:**
- Re-seizes task tree (second and final freeze)
- Runs final dirty-page scan
- Sends remaining dirty pages
- Detects VMAs that appeared after Phase 1, ships those
- Writes "skeleton" CRIU image (all process state except page contents)

**Target:**
- Receivers keep buffering; drain deferred

### Phase 4: Unfreeze + Drain + Restore

**Source:**
- Sends every skeleton image file over TCP
- Signals "all pages sent"
- Unfreezes task tree (or kills if one-way migration)
- Waits for target ACK off critical path

**Target:**
1. Sends immediate ACK (source unblocks)
2. `criu restore` processes skeleton image
3. Builds task tree, freezes new tasks
4. Drain threads apply buffered pages via `UFFDIO_COPY`
5. Once buffer empty, unfreezes tasks — migration complete

## Kernel Interfaces

CLONE dump relies on several Linux kernel features:

### userfaultfd with WP_ASYNC

Write-protect mode marks pages read-only. When the application writes:
- Kernel allows the write to proceed (async mode)
- Sets the soft-dirty bit for later detection
- No userspace round-trip per write

Requires `UFFD_FEATURE_WP_ASYNC` (Linux 6.1+).

### PAGEMAP_SCAN

Efficient bulk query for dirty pages:
- Single ioctl scans large address ranges
- Filters for specific page states
- Optionally clears dirty bits atomically while scanning

Requires Linux 6.7+.

### process_vm_readv

Reads memory directly from target process without copying through kernel buffers. Used by sender threads to fetch page contents.

### UFFD Events

userfaultfd delivers `UFFD_EVENT_UNMAP` and `UFFD_EVENT_REMOVE` when the process unmaps memory. A dedicated reader thread consumes these events and records unmapped ranges.

## Wire Protocol

Page data flows over parallel TCP connections with LZ4 compression.

**Format per batch:**
1. Standard `page_server_iov` header
2. Four-byte `compressed_size`
3. LZ4 payload

Design decisions:
- Per-batch compression (one LZ4 frame per batch), not streaming
- Keeps receiver decompressions independent — no shared state between threads
- LZ4 acceleration parameter set to 1 (higher values regress wall-clock)

## Handling Edge Cases

### New VMAs

VMAs registered at Phase 1 are a snapshot. The process may `mmap()`, `mprotect()`, or `brk()` during Phase 2.

**Solution:** At Phase 3, re-collect live VMA list and compare to Phase 1 set. New regions treated as fully dirty — every page queued for transfer.

Covered scenarios:
- Freshly-mapped regions
- Extensions of existing VMAs
- Regions unmapped then re-mapped at same address

### Unmapped Regions

Two detection mechanisms:

1. **Kernel signal:** userfaultfd delivers `UFFD_EVENT_UNMAP` / `UFFD_EVENT_REMOVE`
2. **Fallback:** `process_vm_readv` returns `EFAULT` for unmapped regions

Both paths converge on a single unmapped-range set. At Phase 3:
- Unmapped ranges dropped from lazy-VMA list
- Target drops buffer entries for unmapped ranges before drain

## TLS Support

Optional TLS wrapping for P3 sockets:
- Implementation in `tls-conn.c` using GnuTLS
- Single credentials object built at startup
- Each P3 socket gets own session reusing shared credentials
- Same certificate/key/CA paths as existing `--tls` flag
- Compression logic identical with or without TLS

## Configuration

### Invocation

**Source:** Add `--clone-dump` to dump command

**Target:** Use dedicated `criu clone-receive` mode

```bash
# Target host
sudo criu clone-receive \
    --images-dir /tmp/img \
    --address <source-ip> --port 27 -v4

# Source host
sudo criu dump -t <pid> \
    --images-dir /tmp/img \
    --clone-dump \
    --page-server --address <target-ip> --port 27 -v4
```

### Runtime Tunables

| Option | Default | Effect |
|--------|---------|--------|
| `--clone-dump` | off | Enables phased dump path |
| `--clone-p3-threads N` | 15 | Page-sender threads (and matching receivers) |
| `--clone-p3-threads-bulk N` | 15 | Senders active during bulk pass |
| `--clone-scanners N` | 20 | Scanner threads for `PAGEMAP_SCAN` |
| `--clone-pre-scanners N` | 1 | Scanners active during Phase 2b |
| `--clone-drain-threads N` | 20 | Target-side `UFFDIO_COPY` threads |
| `--clone-pre-scan` | off | Enables Phase 2b iterative pre-freeze convergence |
| `--tls` | off | Wraps P3 sockets in TLS |

## Requirements

- **Linux 6.7+** on both source and target
  - `UFFD_FEATURE_WP_ASYNC` (kernel 6.1+)
  - `PAGEMAP_SCAN` (kernel 6.7+)
- Unprivileged userfaultfd enabled:
  ```sh
  sudo sysctl -w vm.unprivileged_userfaultfd=1
  ```
- TCP reachability from source to target

## Known Limitations

1. **Single process tree** — Tracking metadata is shared-global; only one CLONE dump at a time per CRIU instance
2. **Kernel requirements** — Linux 6.7+ mandatory; no fallback for older kernels
3. **UFFD cleanup** — Page-table walks during `UFFDIO_UNREGISTER` can take seconds on very large memory; cleanup is chunked

## Future Improvements

1. **Multi-process tree support** — Remove global singletons to allow concurrent migrations
2. **Adaptive convergence threshold** — Driven by measured write rate rather than fixed threshold
3. **WP_SYNC support** — Switch from async to synchronous write-protect during convergence; writes to shipped pages block until re-fetched, bounding worst-case dirty set

## See Also

- [Memory Changes Tracking](memory-changes-tracking.md) — Soft-dirty bit and `PAGEMAP_SCAN`
- [Userfaultfd and Lazy Migration](userfaultfd.md) — UFFD basics and lazy pages
- [Memory Dumping and Restoring](memory-dumping-and-restoring.md) — Standard memory handling
- [Full CLONE Dump Design Specification](https://asafpamzn.github.io/criu/clone-dump-design.html) — Comprehensive external documentation
