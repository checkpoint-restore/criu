# Plan: Parallel private-memory fill in host code (keep complexity out of the PIE)

Status: M0-M2 implemented (jj `b38b6b3e`, "mem: host-side parallel fill for
private-anon VMA content (M0-M2)"), pending verification on a privileged
machine. See §6 "Implementation notes" for how the landed code diverges from
the sketch below, and §7 "Open items" for what M1's exit criterion still
needs.
Date: 2026-09-21
Relates to: [[multithreaded-pie-restore-design]] (the PIE-threading design this
is the alternative to)
Series under review: jj `nnmkzvzv::ypukpnkw`
Source analysis: criu/mem.c, criu/pie/restorer.c, criu/pagemap.c,
criu/cr-restore.c, criu/asyncd.c, criu/util.c

## 0. What the reviewer is asking for

The current series parallelizes the eager private-anon memory fill **inside the
restorer PIE** (`restore_vma_preadv_parallel()` in `ypukpnkw`): a pool of
ephemeral worker threads cloned with `CLONE_THREAD | CLONE_CHILD_CLEARTID`, an
atomic work-stealing cursor, a hand-rolled futex join, and the tree-wide
`last_pid_mutex` held across the whole spawn/fill/join window so worker TIDs
cannot collide with the exact TIDs the real-thread clone loop reproduces later.

That machinery — plus `psoosuyt` (making `RUN_CLONE_RESTORE_FN`'s asm labels
unique so the clone macro can be instantiated twice) and the TID-collision
hardening (design §3, milestone M2, risk §7) — exists **only** because the PIE
is a freestanding `CR_NOGLIBC` blob that cannot call `pthread_create`.

The reviewer's request: **do the parallel fill in ordinary linked C code
instead, and hand already-filled VMAs to the PIE.** Benchmark that first. If it
matches the PIE approach, the entire worker pool + TID hardening + asm-label
change is *deletable* — we remove complexity instead of adding it.

> Note on the reviewer's literal diff. The suggested patch deletes `pr->pieok`
> from the `mem.c:1205` guard. That is inverted: removing a term from that AND
> routes *more* VMAs onto the PIE fill path, the opposite of the stated goal.
> The correct lever is to force the *premap* branch (make `pieok` false, or
> size-gate a force), so every private VMA is filled host-side. The intent is
> right; only the mechanism in the sketch is backwards.

## 1. Why host-side C is allowed here (the key insight)

The "no libc / no malloc / only `sys_*`" rule applies **only to the PIE blob**,
not to the fill. Two distinct bodies of code run in the target process, in
sequence:

**Phase A — ordinary CRIU restore code (fully linked: libc, malloc, pthreads).**
`restore_task_with_children → restore_one_alive_task → prepare_mappings →
restore_priv_vma_content` (`cr-restore.c:1658`, `mem.c:1236`). This is normal C.
It *already* calls `posix_memalign` (mem.c:1354) and `xmalloc`, links glibc, and
uses `mmap`/`preadv`. It runs in the target's address space and namespaces, but
the target is still "CRIU-shaped": the CRIU binary is mapped, service fds are
open, a heap exists, and pthreads can be spawned freely. **This is the "host"
side. Adding a pthread pool here pulls in nothing new.**

**Phase B — the restorer PIE blob (freestanding, `CR_NOGLIBC`).**
`__export_restore_task` in `pie/restorer.c`. This is where the "no libc" rule
lives, and it is the code the current patch adds threading to — hence the
custom clone/futex/TID machinery.

### 1.1 What "host" means

Not a separate helper process. It is the *same* process that becomes the
restored task, running its fully-linked CRIU code during the early restore
stages, **before** it jumps into the PIE. Because `prepare_mappings` already
runs inside the target's own address space, host code can populate the target's
final memory directly.

### 1.2 Why Phase A's dependencies and side effects don't leak into Phase B

Between A and B, **everything from Phase A is unmapped.** The PIE's first acts
include `unmap_old_vmas()` (`restorer.c:2340`), which tears down the old CRIU
address space, leaving only the `bootstrap` region (PIE blob + args) and the
premapped-VMA reservation. Therefore:

- **malloc arenas / per-thread arenas** live in the old CRIU mappings; unmapped
  wholesale before `sigreturn` into the app. They never coexist with the
  restored process's final map.
- **pthreads** are `pthread_join`ed at the end of the fill, before Phase B;
  their stacks are old CRIU mappings and get unmapped too.
- **libc side effects** (locale, TLS, signal state) are all in the discarded
  mappings; the restored process's state comes entirely from the core/sigframe.

The filled content survives because it lives in the premap reservation
(`premmapped_addr`), which `unmap_old_vmas` deliberately preserves; the PIE then
`mremap`s it to the final address — a page-table move, **no copy**
(`restorer.c:2350-2382`).

### 1.3 How host code sets up VMAs for the PIE (the premap path)

This mechanism already exists and already runs today for the streamer,
incremental (parent), and `--lazy-pages` modes (all of which have
`pr->pieok == false`):

1. `premap_private_vma()` (`mem.c`) `mmap`s the VMA's destination into a scratch
   reservation (`rsti(t)->premmapped_addr`), records `premmaped_addr`, sets
   `VMA_PREMMAPED`.
2. `restore_priv_vma_content()` fills those pages host-side with normal
   `preadv`/`read_pages` — full libc, no freestanding constraints.
3. The PIE later `vma_remap()`s each `VMA_PREMMAPED` region from the reservation
   to its final address. No copy.

So "host sets up VMAs for the PIE" = *map and fill them in a reservation in the
same address space; the PIE only relocates them.*

## 2. The one real caveat (be honest about it)

Host-side fill threads still `clone` and thus consume TIDs from the target's PID
namespace during Phase A. This is safe **only because of ordering**: they are
all reaped (`pthread_join`) before the PIE's target-thread TID reproduction
begins, and the legacy path rewrites `ns_last_pid` per target under
`last_pid_mutex` anyway. So the same underlying TID concern is resolved by
*ordering* (join in Phase A) rather than by holding a mutex across a clone loop
inside the PIE. This is strictly simpler and needs neither `psoosuyt` nor a
futex-join.

## 3. Milestones

| # | Deliverable | Exit criterion | Status |
|---|---|---|---|
| M0 | Force all private-anon VMAs onto the premap path (`pr->pieok = false`, or a size-gated force in the `mem.c:1205` guard). `vma_io` goes empty → `ta->vma_ios == NULL` → PIE fills nothing; `restore_priv_vma_content()` fills everything host-side (serial, as today). Benchmark warm-cache multi-GB private-anon restore: host-serial vs current PIE-serial. | Parity or better; confirms the premap detour (VA reservation + one `mremap`/VMA) is cheap. | **Done**, gated by the new `--host-mem-workers` option (see §6.2) rather than an unconditional flip. Rigorous multi-GB parity benchmark not yet run — see §7.1. |
| M1 | Add a `pthread` pool to `restore_priv_vma_content()` (or a sibling driver). Shard delayed/premapped ranges across `min(get_avail_cpus(), MEM_WORKER_MAX)` threads; each worker opens its **own** `page_read` (`open_page_read` is already safe for concurrent opens — asyncd relies on it) and `preadv`s into disjoint, already-mapped destinations. No data-path locking. | zdtm restore suite passes; ≥4× fill throughput vs serial on a multi-GB warm-cache private-anon heap. | **Done, but shaped differently** — see §6.1. zdtm suite not run (no real root available in the implementing sandbox); ≥4× throughput not rigorously measured — see §7.1. |
| M2 | Keep the inherited/COW path (`vma_inherited`, `page_bitmap`/`memcmp` at `mem.c:1338-1386`) correct: simplest cut is to parallelize only straight-read non-inherited ranges and leave COW serial. | COW/dedup correctness tests pass; hole-punch (`auto_dedup`) still lands. | **Done for free** — see §6.1. `auto_dedup` hole-punch reimplemented per-job in the parallel path; not yet exercised by an automated test. |

### 3.1 What this lets us delete (the reviewer's payoff)

- All of `restore_vma_preadv_parallel()` + helpers in `restorer.c` (~285 lines):
  `mem_fill_pool` / `mem_fill_job` / `mem_worker_arg`, `fill_simple_job`,
  `mem_run_job`, `rio_split`, `mem_fill_drain`, `mem_worker_thread`, the
  clone-flags/futex-join block.
- The **entire TID-collision problem** (design §3, M2, risk §7): no clones in
  the PIE → no contention with the real-thread clone loop → no
  `last_pid_mutex`-across-spawn.
- `psoosuyt` (unique `RUN_CLONE_RESTORE_FN` asm labels) — macro instantiated
  once again.
- `xkpwyruv`'s `fill_one_rio` / `rio_next` extraction in `restorer.c`. (The
  `get_avail_cpus()` move to `util.c` is *kept* — the host pool reuses it.)
- `nr_mem_workers` plumbing through `task_restore_args` / `restorer.h`; gating
  (`set_mem_workers`) becomes a host-thread-count choice.

## 4. Tradeoffs to measure / call out

- Premap holds a transient full-VA reservation for the premapped private VMAs
  and adds one page-table `mremap` per VMA in the PIE — cheap, and already paid
  by the streamer/lazy paths today.
- Per-task locality is preserved: each restored task parallelizes its own fill
  in its own process, exactly like the PIE version — no cross-task thread
  accumulation.
- THP loss (4 KiB fills) is identical in both approaches; `MADV_COLLAPSE`
  (design M4) stays orthogonal.
- The O_DIRECT AIO path (`restore_vma_aio`) is untouched by either approach.

## 5. Bottom line

Move the parallel fill *out* of the freestanding PIE and *into* ordinary linked
host code that premaps-and-fills in the target's address space, letting the PIE
keep doing only its cheap `mremap`. If M1 hits the same throughput, we ship the
win while **removing** the clone/futex/TID complexity instead of adding it.

## 6. Implementation notes (what actually landed)

The implementation (jj `b38b6b3e`) follows the strategy above but differs from
the sketch in three ways.

### 6.1 Where the pool lives: draining `pr->async`, not a new driver

The plan's M1 sketch imagined a `pthread` pool bolted onto
`restore_priv_vma_content()` (`mem.c`), with each worker opening its own
`page_read`. The landed code instead parallelizes one level lower, in
`criu/pagemap.c`, by draining the pre-existing `pr->async` queue — the same
list `process_async_reads_ctx()` already walks serially via `preadv`/`memset`.
This queue is exactly the "delayed private-anon range" data M1 wanted to
shard; reusing it means:

- No second `page_read` per worker. All workers share one `pr->pi` fd and use
  `pread`/`preadv` with explicit offsets (no `lseek`), so no per-worker reader
  state is needed at all — simpler than the planned "each worker opens its own
  `page_read`".
- Splitting happens on `struct page_read_iov` entries (`host_fill_split()`),
  not on already-rendered PIE `struct restore_vma_io`. Uncompressed entries
  are cut into 4 MiB (`HOST_MEM_FILL_CHUNK`) pieces so one coalesced
  contiguous-heap entry still parallelizes (same problem the PIE design's
  `rio_split()` solved, solved here on the pre-PIE representation instead).
  Zero/packed-raw entries stay whole-entry jobs, matching the PIE sketch.
- **M2 falls out for free**, more directly than planned: the COW/inherited
  path (`mem.c:1338-1386`) calls `pr->read_pages(..., PR_ASYNC)` then
  `pr->sync()` immediately per-batch and never touches `vma_io`/`pr->async`
  for its own comparisons — only non-inherited delayed ranges ever reach the
  queue this pool drains. No explicit "leave COW serial" branch was needed.
- Encoded (LZ4) entries and O_DIRECT queues are detected up front and bail
  back to the existing serial path (`process_async_reads_ctx()`'s original
  body, unchanged) so this doesn't duplicate or fight the LZ4 worker pool in
  `compression.c`.

Net effect: M1's "shard delayed/premapped ranges" and its own `MEM_WORKER_MAX`
gating are still present, just implemented as `host_fill_split()` +
`process_async_reads_parallel()` operating on the pagemap layer instead of a
new driver bolted onto `mem.c`.

### 6.2 Gating: an explicit opt-in flag, not an unconditional M0 flip

The plan's M0 language ("force all private-anon VMAs onto the premap path")
reads as an unconditional flip once M0 lands. The implementation instead
makes this an explicit, always-available knob: `--host-mem-workers N`
(0 = auto/available CPUs, 1 = serial, **default**, N > 1 = explicit worker
count). Setting it to anything other than `1` is what forces `pr->pieok =
false` (M0) *and* enables the parallel drain (M1) together — there is no
separate flag to force premap without parallelizing, since nothing else would
motivate paying that detour's cost.

This was a size-gated-force in spirit but user-controlled rather than
automatic; no VMA-size or total-bytes heuristic decides serial-vs-parallel on
its own (`process_async_reads_parallel()` does have an internal
`HOST_MEM_FILL_MIN_BYTES` floor, but the top-level on/off switch is the flag).
The flag is plumbed through the CLI (`crtools.c`/`config.c`), RPC
(`images/rpc.proto` + `cr-service.c`, new field `host_mem_workers`), and
`test/zdtm.py` (mirroring how `--image-io-mode` is threaded through, so the
zdtm suite can pass it and exercise the path once run with real root).

### 6.3 What was actually deleted

§3.1's deletion list ("what this lets us delete") is moot in practice: the PIE
threading series (`nnmkzvzv::ypukpnkw`) was never merged into `criu-dev` — it
exists only as sibling jj commits alongside this work, not as code this
change had to remove. This change is additive against the merged tree, not a
revert of already-landed PIE-threading code. If `nnmkzvzv::ypukpnkw` is
abandoned in favor of this series (the expected outcome once §7.1 confirms
parity), that list still describes what to *not* pursue, not what to delete.

## 7. Open items

### 7.1 M1's throughput exit criterion is unverified

The implementing environment had no real root (zdtm needs actual cgroup
mounts and arbitrary `setuid`, which fail even under
`unshare -U --map-root-user`), so M1's "≥4× fill throughput vs serial on a
multi-GB warm-cache private-anon heap" and "zdtm restore suite passes" were
**not** rigorously verified. What was done instead, by hand, inside a user
namespace:

- Byte-exact restore of 64 MiB and 512 MiB private-anon buffers with known
  patterns, across `--host-mem-workers` 0/1/8/16.
- A `stress-ng --vm` dump/restore cycle.
- A rough timing comparison on a 512 MiB cached workload: ~279 ms serial vs
  ~78-107 ms parallel — directionally right, but not the multi-GB benchmark
  M1 asks for, and not a controlled A/B (different process, single run).

**Before this can be considered to have met M1's exit criterion**, run on a
machine with real root:
```
sudo ./test/zdtm.py run -a -f h --host-mem-workers 4
```
plus a dedicated multi-GB warm-cache benchmark (host-serial
`--host-mem-workers 1` vs parallel `--host-mem-workers 0`) to get an actual
throughput ratio.

### 7.2 `auto_dedup` hole-punch in the parallel path is untested

`host_fill_punch()` reimplements the per-range `FALLOC_FL_PUNCH_HOLE` call
inline in the parallel drain (`pagemap.c`), separate from the serial path's
`punch_hole()`/bunch-merging logic. It punches each job's own byte range
individually rather than merging adjacent ranges into one bunch like the
serial path does, which is correct but potentially more `fallocate()` calls
under `--auto-dedup`. Not covered by the manual verification in §7.1; needs a
dedup-enabled zdtm run (`--dedup`) once real root is available.
