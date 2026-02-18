# CRIU COW Dump: Design + Code Map

This document describes the current COW (copy-on-write) live migration design in
this fork, and points to the concrete code paths that implement it.

For setup and how to run the Valkey harness, see `COW_DEVELOPER.md` and
`COW_DUMP_README.md`.

## Goals

1. **Minimize source downtime**: keep the source process running during memory
   transfer (`--leave-running`), instead of freezing it for the full lazy-pages
   duration.
2. **Bring up the replica quickly**: restore and start servicing faults early
   (same core idea as CRIU lazy-pages).
3. **Preserve dump-time semantics**: if the source writes to a page after the
   dump, the replica must receive the **pre-write** contents for the snapshot,
   and later (Valkey) replication catches up.

## Terms (short)

- **PRIMARY / source**: machine running the live workload (e.g. Valkey).
- **REPLICA / destination**: machine restoring from CRIU images.
- **VMA**: a virtual memory area (one mapping range in a process).
- **UFFD WP**: `userfaultfd` write-protect mode; first write generates a fault
  event (`UFFD_PAGEFAULT_FLAG_WP`).
- **lazy-pages / page-server**: CRIU mechanism for transferring pages on-demand.

## Architecture (high level)

```
PRIMARY (source)                                    REPLICA (destination)
──────────────────────────────────────              ─────────────────────────────────────
Valkey (running)                                     CRIU lazy-pages daemon
  ↑  writes                                             ↑   receives page stream / faults
  │                                                      │
CRIU dump process                                        CRIU restore
  ├─ parasite RPC: create UFFD + register VMAs (WP)         └─ installs UFFD handlers
  ├─ apply initial UFFDIO_WRITEPROTECT (parallel)              (faults routed via lazy-pages)
  ├─ COW monitor thread: snapshot pages on WP fault
  └─ page server + unified sender thread: stream pages

Valkey replication (REPLICAOF) ensures the destination catches up after restore.
Scripts keep the replica read-only and gated until replication is configured.
```

## Implementation contracts (current branch)

1. **COW session ownership**
   - COW state is dump-session scoped (`g_cow_info`).
   - Each task in the process tree registers its eligible VMAs and contributes a
     `userfaultfd` to the session.
   - The COW monitor thread is global and started once. It may start during the
     first task dump to service parasite-side write faults.

2. **VMA eligibility and fallback**
   - Only VMAs matching the same filters as lazy-pages page generation are
     eligible for COW tracking (see `criu/cow-dump.c:cow_register_vmas()`).
   - VMAs that cannot be WP-registered are skipped and dumped via the normal
     path.
   - `UFFDIO_REGISTER` is called from the CRIU process (not the parasite);
     the ioctl operates on the uffd's associated `mm_struct`.

3. **Bulk stream termination (no ACK)**
   - The sender ends the bulk page stream with an end marker: `PS_IOV_CLOSE`
     header with `nr_pages == 0`.
   - The receiver treats end marker as completion and does not send any ACK back
     on the same socket.
   - The sender tolerates receiver close after the marker (`EPIPE`/`ECONNRESET`
     on send is treated as clean completion).

4. **Teardown ordering**
   - `wait_for_page_server_thread()` happens before `cow_dump_fini()` to avoid
     freeing hash/locks while the sender thread is still running.

## Dump-side flow (PRIMARY)

### CLI entry points

- Option parsing: `criu/config.c` (`--cow-dump` → `opts.cow_dump`)
- Dump coordinator: `criu/cr-dump.c:cr_dump_tasks()`

### Timeline

1. **Seize/freeze**
   - CRIU seizes the process tree (stop-the-world) to build a consistent base.

2. **Per-task COW registration (`dump_one_task()` → `cow_dump_init()`)**
   - File: `criu/cr-dump.c` calls `criu/cow-dump.c:cow_dump_init()`.
   - `cow_dump_init()`:
     - calls parasite RPC only to create a `userfaultfd` and negotiate
       `UFFDIO_API` inside the target process (the parasite sends the fd back
       via `SCM_RIGHTS` and does no VMA registration),
     - registers eligible VMAs with `UFFDIO_REGISTER_MODE_WP` directly from
       the CRIU process (`cow_register_vmas()`); this works because the
       ioctl operates on the uffd's associated `mm_struct`, not `current->mm`,
     - applies initial `UFFDIO_WRITEPROTECT` **from the CRIU process** and
       parallelizes it in 256MB chunks (`COW_WP_CHUNK_SIZE`) using worker threads
       (`cow_task_apply_writeprotect()`),
     - adds the task's `userfaultfd` to the global tracked list.
   - On kernels with `/proc/<pid>/userfaultfd` (6.11+, detected via
     `kdat.has_uffd_proc`), the parasite RPC is skipped entirely.

3. **Start/keep the COW monitor thread**
   - Monitor thread: `criu/cow-dump.c:cow_monitor_thread()` (started via
     `cow_start_monitor_thread()`).
   - Why it can start early: once WP is armed, parasite code can trigger WP
     faults (e.g. TLS/rseq writes). The monitor must service those to avoid
     deadlock in further parasite RPC.

4. **On first write to a protected page**
   - Path: `cow_process_events()` → `cow_handle_write_fault()`.
   - Action:
     1. snapshot the page using `process_vm_readv()` (pre-write contents),
     2. store it in a per-page hash (`cow_hash[...]`),
     3. clear WP via `UFFDIO_WRITEPROTECT(mode=0)`,
     4. wake the faulting thread via `UFFDIO_WAKE`.

5. **Resume early and start page transfer**
   - After the base dump finishes, `criu/cr-dump.c:cr_dump_tasks()` prints
     `PAGE SERVER READY TO SERVE`, resumes the process tree, and runs
     `cr_lazy_mem_dump()` to start lazy transfer with the source running.

6. **Page transfer in bulk mode (page server unified sender thread)**
   - File: `criu/page-xfer.c` (`unified_page_server_thread()`).
   - For each destination image (`dst_id`), the sender walks lazy VMAs and sends
     pages using a 3-tier priority:
     1. queued COW pages (pages that faulted on write),
     2. explicit page requests from the destination (fault-driven),
     3. regular pages (sequential walk of the lazy VMA ranges).
   - Each page send (`send_lazy_vma_page()`):
     - re-checks the COW hash after `process_vm_readv()` to preserve dump-time
       semantics under races,
     - sends a compressed record (`PS_IOV_ADD_F_COMPRESS`) plus payload.

7. **End of stream**
   - The sender sends `PS_IOV_CLOSE` with `nr_pages == 0`
     (`send_image_complete()`), and the receiver closes without ACK.

## Restore-side flow (REPLICA)

The REPLICA runs two processes:

1. `criu lazy-pages --page-server ... --cow-dump`
2. `criu restore --lazy-pages ... --cow-dump`

The lazy-pages daemon receives the page stream and satisfies faults for the
restoring process.

Bulk receiver implementation:

- File: `criu/page-xfer.c:page_server_read_bulk_stream()`
  - reads a continuous stream of `struct page_server_iov` headers + payload,
  - supports compressed pages (`PS_IOV_ADD_F_COMPRESS`),
  - treats `nr_pages == 0` as end-of-transfer and stops without sending ACK.

## Threading model (concrete)

Dump process (PRIMARY):

- main thread: orchestrates dump + resumes process + starts lazy transfer
- `cow-monitor` thread: blocks on `userfaultfd` events and snapshots pages
- `criu-page-srv` thread: streams pages for all active `dst_id` images
- `cow-wp` worker threads: apply initial `UFFDIO_WRITEPROTECT` in parallel

Restore side (REPLICA):

- `lazy-pages` process: reads incoming pages and issues `UFFDIO_COPY` into the
  restoring process as needed
- `restore` process: executes restorer code path and transitions to the restored
  workload

## Measurement and artifacts

`scripts/migrate.sh` creates `artifacts/<run_id>/` with:

- `stats-dump(.json)`: CRIU internal dump stats (`freezing_time`, `frozen_time`,
  pages scanned/written, etc.)
- `source-ping.log` + `source_markers.log`: source PING latency samples +
  phase markers
- `lazy-*.log`: CRIU logs from dump/restore/lazy-pages

Phase analysis:

```bash
python3 scripts/analyze_phase_latency.py artifacts/<run_id>
```

Important nuance: CRIU “frozen time” and client-observed stalls are different
metrics. A local monitor can also be affected by CPU starvation on the same
host; use the traffic harness for app-like KPIs.

## Kernel requirements

- Linux 5.7+ (needs `UFFD_FEATURE_PAGEFAULT_FLAG_WP`)
- root, or `vm.unprivileged_userfaultfd=1`

## Future work (short list)

- Explore `UFFD_FEATURE_WP_ASYNC` for alternative dirty tracking semantics.
- Improve fork/remap handling (`UFFD_EVENT_FORK`, `UFFD_EVENT_REMAP`) for
  process-tree workloads.
- Reduce overhead in hot paths (hash management, allocations, compression).


### Usage
```bash
criu dump --cow-dump --lazy-pages ...
```

## Appendix - Statistics and Monitoring

### COW Tracking Statistics

**Per-Second Logging:**
```
[COW_STATS] events: wr=1234 fork=0 remap=0 unk=0 | 
            ops: copied=1234 unprot=1234 woken=1234 | 
            errs: alloc=0 read=0 unprot_err=0 wake_err=0 
                  read_err=0 eagain_err=0
```

**Metrics:**

| Metric | Description | Good Value | Alert If |
|--------|-------------|------------|----------|
| `wr` | Write faults | Varies | - |
| `copied` | Pages copied | = wr | < wr |
| `unprot` | Pages unprotected | = wr | < wr |
| `woken` | Threads woken | = wr | < wr |
| `alloc_failures` | Allocation failures | 0 | > 0 |
| `read_failures` | Read failures | 0 | > 0 |
| `eagain_errors` | EAGAIN on read | Low | High |

### Page Server Statistics

**Per-Second Logging:**
```
[PAGE_SERVER_STATS] get_pages: reqs=500 with_cow=50 no_cow=450 
                               pages=8000 cow=400 errs=0 | 
                    serve: open2=1 parent=0 add_f=7950 get=500 
                          close=1
```

**Metrics:**

| Metric | Description | Indicates |
|--------|-------------|-----------|
| `reqs` | Total requests | Transfer activity |
| `with_cow` | Slow path taken | COW overlay needed |
| `no_cow` | Fast path taken | Zero-copy efficiency |
| `pages` | Total pages transferred | Bandwidth |
| `cow` | COW pages overlaid | Write activity |

### UFFD Daemon Statistics

**Per-Second Logging:**
```
[UFFD_STATS] reqs=1000(pf:50,bg:950) pages=8000 pipe_avg=180
  PF:  4K=30 64K=15 128K=5
  BG:  4K=100 64K=500 128K=200 256K=100 512K=50
```

**Histograms:**
- **PF (Page Fault):** Destination-initiated requests
- **BG (Background):** Proactive prefetch

**Pipeline Depth:**
- `pipe_avg`: Average in-flight requests
- Target: Close to `max_pipeline_depth` (256)
