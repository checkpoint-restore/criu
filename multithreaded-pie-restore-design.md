# Design: Multithreaded private-memory restore inside the PIE (no lazy-pages)

Status: draft
Date: 2026-09-21
Source analysis: criu/pie/restorer.c, criu/mem.c, criu/pagemap.c,
criu/cr-restore.c, criu/asyncd.c, include/common/lock.h,
criu/include/restorer.h (criu-dev + local AIO/compressed-VMA-IO work)

## 0. Motivation and scope

The driving workload is the same as the lazy-pages note
([[multithreaded-lazy-pages-design]]): restore a single process faster
than the ~1 GB/s single-thread ceiling — concretely a JVM whose heap is
private anonymous memory. That note lifts the ceiling by parallelizing
the **lazy-pages daemon drain**, which requires `--lazy-pages`, a
userfaultfd, and a separate daemon.

This note takes the opposite, complementary route: parallelize the
**eager** private-memory fill that the restorer PIE already performs on
the default (non-lazy) restore path. No userfaultfd, no daemon, no
protocol — the win is delivered on the path most users already run.

The two designs are orthogonal and can ship independently:

| | lazy-pages note | this note |
|---|---|---|
| Restore mode | `--lazy-pages` | default (eager) |
| Parallelized code | daemon drain (`uffd.c`) | PIE fill (`restorer.c`) |
| Needs uffd / daemon | yes | **no** |
| Fills private anon | via page faults | directly, before threads run |

### 0.1 Why the eager PIE path is the right target here

On this tree, ordinary uncompressed private-anon VMAs — the default JVM
heap — are **not** filled host-side. `premap_priv_vmas()`
(mem.c:1100) only premaps VMAs that need CPU decode (LZ4) or exceed the
direct-I/O bound; uniform/lightly-fragmented private ranges take the
faster **delayed** path (mem.c:1308–1318, `pagemap_enqueue_iovec`).
Those delayed ranges are rendered into `args->vma_ios`
(pagemap.c:628, `pagemap_render_iovec`) and filled by the PIE itself.

So for the JVM target the single-threaded bottleneck lives in the PIE,
in `__export_restore_task()`, and that is what we parallelize.

## 1. The bottleneck: one serial fill loop, before threads exist

Inside `__export_restore_task()` (restorer.c:2250) the sequence is:

1. Map every non-premmaped VMA — `restore_mapping()` loop,
   restorer.c:2403–2418. **After this the destination pages exist.**
2. **Fill delayed private ranges — restorer.c:2432–2442.** Dispatches to
   one of:
   - `restore_vma_preadv_mixed()` (restorer.c:1842): serial
     `for i < vma_ios_n` loop, each entry a blocking `sys_preadv`
     (restorer.c:1940, `restore_vma_preadv_one`).
   - `restore_vma_aio()` (restorer.c:2007): batched native AIO
     (`AIO_BATCH = 128`), I/O overlapped but driven by a **single**
     submit/reap thread.
3. Clone the task's real threads — restorer.c:2626–2698.
4. `restore_finish_stage(CR_STATE_RESTORE)` — restorer.c:2719.

Step 2 runs while the task is **single-threaded**, strictly between the
mapping loop and thread creation. For a warm page cache — the
meaningful JVM baseline (see lazy note §5) — the cost is the kernel
`copy_to_user` inside `preadv`, which is CPU-bound and embarrassingly
parallel. That is the throughput we are leaving on the floor.

## 2. Why this is tractable: the jobs are already thread-ready

Three properties make the fill parallelizable with almost no reshaping:

1. **Jobs are self-contained value types.** Each `struct restore_vma_io`
   (restorer.h:139) carries its own file offset (`off`), storage kind,
   and a scatter list of destination iovecs. There are no pointers back
   into a mutable list and no shared cursor — unlike the host-side
   `page_read`, the PIE never seeks. `restore_vma_aio()` already
   materializes a flat `rio_ptrs[]` index over the packed array
   (restorer.c:2053).
2. **Reads are offset-explicit and share-safe.** Content comes from one
   fd, `args->vma_ios_fd`, via `preadv(fd, iovs, nr, off)` / AIO
   `IOCB_CMD_PREADV`. `pread`-family calls carry their own offset and do
   not touch the fd's file position, so N threads can read the same fd
   concurrently with no locking.
3. **Destinations are disjoint.** Each job writes into a distinct,
   already-mapped VMA subrange. No two jobs overlap, so concurrent fills
   need no write serialization — the exact bet `asyncd.c` makes for
   shmem/memfd content, applied to private anon.

The PIE also already ships the primitives: futex/mutex/atomics
(`include/common/lock.h`, usable under `CR_NOGLIBC`), the staged-barrier
idiom (`restore_finish_stage`, restorer.h:342), and arch clone macros
(`RUN_CLONE_RESTORE_FN`).

## 3. The one real obstacle: TID collision

This is why the lazy note (§1) said "restorer-PIE constraints" rule out
pthreads, and it is the crux here.

The restorer must recreate each thread with its **exact original TID**
(Documentation/under-the-hood/pid-restore.md). Two mechanisms
(restorer.c:2626–2698): clone3 `set_tid` (race-free, kernel ≥ 5.5), or
the legacy `ns_last_pid` write serialized under
`task_entries_local->last_pid_mutex`. Both fail hard on
`ret != thread_args[i].pid` (restorer.c:2687).

Every `clone` — including any helper we add — consumes a TID from the
kernel's single global sequence. A helper thread that grabs a TID which
a not-yet-created target thread needs breaks restore:
`set_tid` returns `-EEXIST`, or the legacy path lands on the wrong TID.

**Design rule: worker threads are created and fully reaped strictly
inside the fill window (between restorer.c:2418 and 2626), and their
TIDs are released before the target-thread clone loop runs.**

Concretely:

- Clone workers with `CLONE_VM | CLONE_FILES | CLONE_FS | CLONE_SIGHAND
  | CLONE_THREAD` plus **`CLONE_CHILD_CLEARTID`**, pointing
  `child_tid` at a per-worker `futex_t`. On worker exit the kernel
  zeroes that word, wakes the futex, **and frees the TID**. The leader
  `futex_wait`s each worker's clear-tid word to 0 before proceeding —
  a hand-rolled join that guarantees TIDs are back in the pool before
  the target clone loop starts. This is exactly how libc `pthread_join`
  detects exit; we reuse the mechanism with `sys_futex` directly.
- Do **not** assign worker TIDs via `set_tid` — we have no spare TIDs.
  Let the kernel allocate; because workers are joined before the target
  loop, their transient TIDs cannot collide with a target `set_tid`,
  and on the legacy path the per-target `ns_last_pid` rewrite
  (restorer.c:2669, still under `last_pid_mutex`) makes prior
  consumption irrelevant.
- The other hard rule — "no cross-task sync after
  `CR_STATE_RESTORE_CREDS`" (restorer.c:2796) — is not touched: all
  worker activity finishes before `restore_finish_stage(CR_STATE_RESTORE)`
  at 2719, well before creds.

Because the workers only ever `pread`+`memset` into their own address
space and touch no other task, they are invisible to the cross-task
stage barriers and to `compel_stop_tasks_on_syscall`.

### 3.1 Rejected alternative: reuse the target threads as fillers

We could clone the real threads first, then have leader+siblings
cooperatively drain the job queue before each sigreturns. Rejected: it
reorders thread restore relative to memory fill, the siblings carry
restored TLS/rseq/sched state and are moments from `rt_sigreturn` into
app code, and it entangles the fill with the stage barriers. Ephemeral
workers keep the fill a self-contained, single-task-local phase.

## 4. Architecture

```
__export_restore_task() (leader, single-threaded here)
  map VMAs (restorer.c:2403)          <- destinations now exist
  if (nr_mem_workers > 1 && vma_ios big enough):
      build rio_ptrs[] index over args->vma_ios      (once)
      clone W workers on scratch stacks (CLONE_CHILD_CLEARTID)
      each worker:
          while ((k = atomic_fetch_inc(&cursor)) < n)
              fill_one(rio_ptrs[k])   // preadv/AIO/memset, per §2
          exit  -> kernel clears child_tid futex, frees TID
      leader: futex_wait each worker clear-tid word == 0   // join
      check shared atomic error flag
  else:
      restore_vma_preadv_mixed(args)  // existing serial fallback
  ...
  clone real threads (restorer.c:2626)   <- worker TIDs already freed
```

- **Work distribution: atomic work-stealing cursor.** One
  `atomic_t cursor`; each worker claims the next job with
  `atomic_inc_return`. Self-balancing regardless of per-range size, and
  the leader participates as worker 0 so W=1 degenerates to the current
  behavior with no extra thread.
- **`fill_one()` is the existing per-entry code**, factored out of
  `restore_vma_preadv_mixed()`: `VMA_IO_UNCOMPRESSED`/`PACKED_RAW` →
  `restore_vma_preadv_one()`; `VMA_IO_ZERO` → `memset`;
  `validate_direct_vma_io()` unchanged. `auto_dedup` `FALLOC_FL_PUNCH_HOLE`
  stays inline and per-worker — distinct offsets on a shared fd are
  independent.
- **Error propagation:** a shared `atomic_t` error flag; a worker that
  hits an error sets it and stops claiming. The leader fails the restore
  (`goto core_restore_end`) if it is set after join. No new abort path.
- **fd closing** moves from `fill_one` to after the join (today
  `restore_vma_preadv_mixed`/`restore_vma_aio` close `vma_ios_fd`
  themselves; the parallel driver owns the single close).

### 4.1 Pool sizing, stacks, gating

- **Count.** Compute host-side and pass down:
  `ta->nr_mem_workers = min(get_avail_cpus(), MEM_WORKER_MAX)`,
  mirroring `asyncd.c:80` (`ASYNC_THREAD_NR_MAX = 16`). Computing on the
  host avoids `sched_getaffinity` in the PIE and lets an option/env knob
  cap it. Store in `struct task_restore_args`.
- **Stacks.** Workers need a stack but no sigframe. Extend the bootstrap
  allocation (cr-restore.c:3287–3288, where `memzone_size` for the
  per-thread `restore_mem_zone` array is computed) with a
  `nr_mem_workers`-sized array of worker stacks (reuse
  `RESTORE_STACK_SIZE = 32K`, or a lighter zone). One contiguous mmap,
  freed with the rest of the bootstrap region.
- **Gating (lazy start).** Only spin up the pool when the work justifies
  it — e.g. total `vma_ios` bytes over a threshold (a few MiB) and
  `vma_ios_n > 1`. Small tasks keep the zero-overhead serial path, same
  spirit as asyncd's lazy fork.
- **Per-task pools.** Each restored process runs its own PIE and its own
  pool, reaped immediately, so cross-task thread count never
  accumulates. The single-big-process JVM target is the sweet spot.

### 4.2 AIO interaction

The buffered `preadv` path is the primary win (warm-cache
`copy_to_user` is CPU-bound and scales with threads). The O_DIRECT AIO
path (`restore_vma_aio`) already overlaps I/O on one thread; sharding it
(one `aio_context_t` per worker over a disjoint `rio_ptrs[]` slice) is a
straightforward follow-up but secondary — its bottleneck is DMA
bandwidth, not CPU copy. M1 parallelizes preadv; AIO sharding is M3.

## 5. Milestones

| # | Deliverable | Exit criterion | est. LOC |
|---|---|---|---|
| M1 | Factor `fill_one()` out of `restore_vma_preadv_mixed`; add worker-pool driver (clone + CLONE_CHILD_CLEARTID join + atomic cursor + error flag); host-side `nr_mem_workers` + worker-stack allocation; gate on work size | zdtm restore suite passes; ≥4× fill throughput vs serial preadv on a multi-GB warm-cache private-anon heap | ~220 |
| M2 | TID-collision hardening + tests: force legacy `ns_last_pid` path and clone3 `set_tid` path; assert no `-EEXIST`/`ret != pid` under many-thread targets | zdtm multi-thread + `pidns`/`ns_last_pid` tests pass with pool enabled | ~60 |
| M3 | Shard the O_DIRECT AIO path across workers (per-worker aio context over disjoint slices) | AIO path parity + speedup on O_DIRECT restore | ~120 |
| M4 | THP re-collapse via `process_madvise(MADV_COLLAPSE)` after fill (kernel ≥ 6.1, gated) — `preadv` installs 4 KiB pages, same hit the lazy note calls out | measured huge-page recovery on a big heap | ~80 |

M1+M2 is the demoable, independently shippable cut (~280 LOC). Total
~**450–480 LOC** of new/changed C, all in `restorer.c`, `mem.c`,
`cr-restore.c`, `restorer.h`.

## 6. Testing

- zdtm restore suite (default, non-lazy) with the pool forced on:
  single-thread parity first, then multi-worker. Multi-thread-target and
  `ns_last_pid`/pidns tests exercise §3 (M2).
- Throughput: multi-GB private-anon workload, warm cache; compare PIE
  fill wall-clock serial vs pooled. Baseline is buffered `preadv` with a
  warm cache — the meaningful JVM baseline (per lazy note §5), not the
  cold-cache O_DIRECT path.
- Correctness: byte-compare filled memory against source pages; verify
  `auto_dedup` hole-punching still lands (per-worker, disjoint offsets).

## 7. Risks

- **TID collision (§3)** is the primary correctness risk. The
  "join-before-target-clone" fence with `CLONE_CHILD_CLEARTID` is the
  conservative default; M2 tests both clone paths explicitly.
- **PIE code size / freestanding constraints:** workers may use only
  `sys_*` + `common/lock.h` primitives — no libc, no malloc. Keep the
  driver minimal; all buffers come from the pre-sized bootstrap
  allocation.
- **Worker-stack memory:** `nr_mem_workers * 32K` per task, freed with
  the bootstrap region. Cap `MEM_WORKER_MAX` and gate on work size.
- **THP loss:** `preadv` fills 4 KiB pages, so a freshly filled JVM heap
  has no transparent huge pages until khugepaged catches up — a real
  post-restore throughput hit. M4 addresses it; not optional for
  throughput-sensitive heaps.
- **Interaction with `--lazy-pages`:** out of scope by construction —
  lazy ranges are skipped host-side (mem.c:1274) and never enter
  `vma_ios`. This feature only accelerates the eager path and composes
  cleanly with the lazy-pages design as a separate effort.
