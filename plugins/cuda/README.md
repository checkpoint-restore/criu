Checkpoint and Restore for CUDA applications with CRIU
======================================================

# Requirements
The `cuda_plugin` build and install targets provide one CRIU plugin,
`cuda_plugin.so`. It contains two private checkpoint backends so the same CRIU
deployment can run on nodes with different NVIDIA driver versions:

* On r580 and newer drivers, the plugin uses the CUDA Driver API directly.
* On older supported drivers, such as r565 and r570, it invokes the
  `cuda-checkpoint` utility. That utility must be in `PATH` and must support the
  `--action` option. Restores that request GPU remapping also require its
  `--device-map` option.

Backend selection happens once when the plugin is initialized. The Driver API
backend is preferred when `libcuda.so.1` reports CUDA Driver API version 13000
or newer and exports every required checkpoint symbol. Otherwise the plugin
probes the CLI backend. A selected backend is never replaced after an operation
starts: lock, checkpoint, restore, and unlock errors are fatal and do not cause
fallback.

Users can override automatic selection with the plugin-specific `backend`
option:

```
--plugin-option=cuda_plugin.backend=auto
--plugin-option=cuda_plugin.backend=driver-api
--plugin-option=cuda_plugin.backend=cuda-checkpoint
```

`auto` is the default. Once CUDA handling is activated, an explicit
`driver-api` or `cuda-checkpoint` selection probes only that backend and fails
plugin initialization when it is unavailable; it never falls back to the other
backend. In particular, `cuda-checkpoint` forces the older CLI interface even
when the Driver API backend is supported. A dump on a host without an NVIDIA
GPU still disables the optional plugin before probing a backend. The CUDA
plugin ignores namespaced arguments it does not recognize so other plugins can
parse the same list. Unknown and empty `cuda_plugin.backend` values are
rejected. The plugin validates recognized arguments during initialization,
including pre-dump and CPU-only restore, but does not probe a backend for either
of those cases.

CRIU records the stable logical name `cuda_plugin` in its image inventory. It
does not record the selected backend or NVIDIA driver version, so an image
dumped with one backend can be restored with the other. Workloads that depend
on capabilities from a newer driver still require those capabilities on the
restore host. If an override is required for both operations, pass the option
separately to the dump and restore commands.

During restore, the plugin does not probe either backend unless the image
requires `cuda_plugin`. It consumes that requirement only after one backend has
been selected and initialized. If neither backend is supported, normal CRIU
inventory validation reports the missing required plugin.

Images created before plugin inventory was introduced retain CRIU's legacy
compatibility behavior and initialize every available plugin during restore.

## CUDA Driver API backend
The direct backend loads `libcuda.so.1` dynamically and uses these symbols:

* `cuDriverGetVersion`
* `cuInit`
* `cuCheckpointProcessLock`
* `cuCheckpointProcessCheckpoint`
* `cuCheckpointProcessRestore`
* `cuCheckpointProcessUnlock`
* `cuCheckpointProcessGetState`
* `cuCheckpointProcessGetRestoreThreadId`

It also uses `cuGetErrorName` and `cuGetErrorString` for error messages when
libcuda exports them.

The direct backend does not require CUDA toolkit headers at build time. The
`cuDriverGetVersion` threshold deliberately prevents it from using the mirrored
CUDA 13.0 restore ABI on older drivers merely because checkpoint symbols are
present.

During checkpoint and restore, the Driver API backend calls libcuda in a
worker thread while CRIU's tracing thread waits for the CUDA restore thread.
After the API call returns, the worker sends SIGSTOP to the restore thread.
CRIU consumes this ptrace stop and restores the thread's signal mask and
ptrace options without forwarding SIGSTOP.

If the restore thread stops unexpectedly or exits before the operation
completes, CRIU kills the target process with SIGKILL. Closing the target's IPC
sockets allows the blocked Driver API call to return, after which CRIU joins
the worker. The plugin then starts no new lock or checkpoint, but rollback
still restores the other tasks. The target cannot resume after this recovery
path. Driver API calls and worker
joins have no deadline; a driver call that remains blocked can still hang CRIU.

The CLI backend executes `cuda-checkpoint` for each request and monitors the
CUDA restore thread while waiting. Unexpected stops or exits fail the operation
regardless of the configured timeout. By default, helpers have no deadline, so
large checkpoints and restores can take as long as needed. To impose a limit:

```
--plugin-option=cuda_plugin.timeout=600
```

The value is a nonnegative number of seconds; the default, `0`, means unlimited.
A positive value gives each CLI invocation one deadline covering all output
reads and helper exit, including capability probes and state queries. It does
not impose a deadline on in-process Driver API calls. CRIU's `--timeout` is
separate: it controls task freezing and is also passed to CUDA's native lock
operation by both backends. With the default helper timeout, a silent helper
hang can wait indefinitely even though unexpected restore-thread stops and
helper exits are still detected.

The CLI backend uses finite internal budgets when waiting for an interrupted
restore thread to stop or for a terminated helper to exit. These waits remain
bounded even when `cuda_plugin.timeout=0`. If a lock helper times out and is
terminated and reaped, rollback queries the task's state and unlocks it after
CRIU cancels its freezing alarm. These recovery helpers ignore the expired
freezing timer and honor `cuda_plugin.timeout`, including zero for unlimited.
A helper failure while the restore thread is running, or a helper that cannot
be terminated and reaped, leaves that task's CUDA state unknown. The plugin
then starts no new lock or checkpoint and skips that task during rollback, but
still rolls back the other tasks. Terminating a helper does not establish that
CUDA state was rolled back: GPU state may remain locked or partially
checkpointed, and the application may need to be restarted. The plugin cannot
recover a CUDA job after a fatal driver fault.

The plugin contains independently authored declarations for the CUDA checkpoint
argument structures because CRIU does not build against the CUDA toolkit
headers. These declarations describe the ABI used by the plugin; they are not a
general-purpose CUDA header. Reserved fields are zeroed and must not be
repurposed without an explicit driver-version check and verification of the
corresponding CUDA release.

## GPU device mapping

During a CUDA dump, the plugin saves the ordinal and UUID of each GPU in the
plugin-private `cuda-gpu-inventory.img` image. It enumerates the GPUs before it
locks the first CUDA task. If enumeration fails, the dump continues without the
inventory. During restore, an optional
`cuda_plugin.device-map` setting can remap every checkpoint GPU to a compatible
GPU on the destination host. The setting is restore-only; passing it to dump or
pre-dump is an error.

An explicit UUID map uses the same syntax as `cuda-checkpoint`. This example
swaps the first two GPUs and leaves two others in place:

```bash
criu restore ... \
  "--plugin-option=cuda_plugin.device-map=$GPU_0=$GPU_1,$GPU_1=$GPU_0,$GPU_2=$GPU_2,$GPU_3=$GPU_3"
```

The saved inventory also permits ordinal mappings. The left ordinal identifies
a GPU in the dump-time CUDA view and the right ordinal identifies a GPU in the
restore-time view:

```bash
criu restore ... --plugin-option=cuda_plugin.device-map=0=1,1=0,2=2,3=3
```

`auto` maps each checkpoint GPU to the destination GPU with the same ordinal:

```bash
criu restore ... --plugin-option=cuda_plugin.device-map=auto
```

Omitting the setting keeps the original UUIDs. By contrast, `auto` permits the
UUIDs to change while preserving ordinal order. A map that uses ordinals must
cover each checkpoint GPU exactly once. A UUID-only map may list fewer GPUs,
because the inventory records CRIU's view, which can include GPUs that the
checkpointed processes cannot see; CUDA rejects a map that omits a GPU visible
to a process. Every destination UUID must be present on the restore host.
Images without the private GPU inventory are compatible with explicit
UUID-to-UUID maps, but cannot use ordinals or `auto`.

The common mapping code resolves every form to UUID pairs. The Driver API
backend passes those pairs in `CUcheckpointRestoreArgs`; the CLI backend formats
the same pairs for `cuda-checkpoint --device-map`. This keeps the inventory and
mapping semantics independent of which backend performed dump or restore.

GPU enumeration runs in a short-lived helper under either backend and uses
the same `cuda_plugin.timeout` setting. A positive value supplies one deadline
for the reply header, GPU UUIDs, end of output, and helper exit; partial reads
do not restart it. Zero permits an unlimited wait, including inside driver
initialization. On failure, the plugin terminates the helper and waits for its
exit with a separate finite internal budget.

GPU enumeration honors `CUDA_VISIBLE_DEVICES` and `CUDA_DEVICE_ORDER`; the
plugin never widens CRIU's CUDA view. All checkpointed CUDA processes must
share that view, and CRIU must run with the same dump-time or restore-time view
as the corresponding processes. The private inventory is not a core CRIU image
type, so CRIT does not decode or rewrite it.

# Checkpointing Procedure
Both backends expose 4 actions used in the checkpointing process: lock,
checkpoint, restore, and unlock.

* lock - Used with the PAUSE_DEVICES hook while a process is still running to
  quiesce the application into a state where it can be checkpointed
* checkpoint - Used with the CHECKPOINT_DEVICES hook once a process has been
  seized/frozen to perform the actual checkpointing operation
* restore/unlock - Used with the RESUME_DEVICES_LATE hook to restore the CUDA
  state and release the process back to it's running state

These actions are facilitated by a CUDA checkpoint+restore thread that the CUDA
plugin will re-wake when needed. During the `CHECKPOINT_DEVICES` hook, CRIU
temporarily resumes this thread with seccomp filters active and verifies
afterward that no new tasks or threads were created in the target process tree.
However, if the root of the checkpointed process tree is not PID 1 of a PID
namespace, a resumed thread calling `clone()` or `clone3()` with
`CLONE_UNTRACED` (for example with `CLONE_PARENT` or by double-forking) could
bypass `PTRACE_O_TRACECLONE` and create an untraced process outside the
checkpointed tree. When checkpointing untrusted workloads, it is therefore
recommended to blacklist `CLONE_UNTRACED` using seccomp filters.

# Processes Forked After CUDA Started

When a process that started CUDA calls fork() without exec(), the worker
inherits its NVIDIA descriptors and some of its mappings. Only the calling
thread survives in the worker, so it has no CUDA restore thread. The NVIDIA
driver marks managed UVM mappings `VM_DONTCOPY` by default. Other mappings,
including shared system memory mapped through `/dev/nvidiactl`, can remain
accessible to the worker even if it never calls CUDA. PyTorch's inductor,
for example, compiles in workers forked from a process that queried the GPU.

By default the plugin stops the dump if its scan finds NVIDIA mappings or
descriptors in such a worker. Use the following dump option only if the
application can release those address ranges and use `/dev/null` in place of
the affected open files wherever they are referenced.

```sh
criu dump ... --plugin-option=cuda_plugin.fork-inherited=discard
```

Once the whole tree is frozen and before the first CUDA task is checkpointed,
the plugin checks every descendant of a CUDA task that has no CUDA state of
its own. The scan covers character-device majors registered exclusively under
NVIDIA driver names in `/proc/devices`. Each mapping must match a CUDA
ancestor's device, inode, address range and file offset. Each descriptor must
refer to the same open file as one held by a CUDA ancestor (`kcmp(KCMP_FILE)`).
With discard enabled, CRIU omits the matching mappings and restores the
descriptors on `/dev/null`, preserving their numbers. The plugin writes their
file IDs to `cuda-inherited-files.img` after dumping all tasks and adds
`cuda_plugin.inherited-files` to the inventory. If that entry is present,
restore requires the file and reads it before forking. The CUDA tasks
themselves are checkpointed as usual.

The dump fails before any CUDA task is checkpointed if the scan finds
NVIDIA state in a descendant that cannot be matched, for example a device
it opened itself or a mapping its CUDA parent has since dropped. The log
names the task and the unmatched mapping or descriptor. If a previous dump
checkpointed a CUDA task and then resumed it, that task may now hold different
open files or mappings from the ones its descendants inherited.

When a user namespace prevents CRIU from following `/proc/PID/map_files`,
the scan uses a pathname only if its filesystem device and inode match the
mapping. CRIU handles any unresolved mapping during its normal VMA scan. An
unsupported device mapping in that case can fail the dump after the CUDA
ancestor has been checkpointed.

The checks use the state visible when CRIU freezes the tree. An independently
created mapping of the same device inode at the same addresses and offset is
indistinguishable from a forked copy. CRIU also assigns one file ID to every
reference to the same open file description. If the application passed that
file to another task or queued it on a Unix socket, those references will
also refer to /dev/null on restore. The placeholder opens read-write and
has the file status flags and operations of /dev/null.

# Testing

The CPU-only regression tests exercise both backends with mock CUDA APIs and
real ptrace stops, including separate restore threads in multithreaded targets,
Driver API worker completion and target termination after faults, unrelated
child events, unlimited and finite CLI waits, helper exits, bounded CLI
post-call stop waits, and rollback:

```
make cuda_plugin
make -C test/cuda-checkpoint test
sudo python3 test/cuda-checkpoint/backend-errors.py
```

Real CUDA workloads are still needed to validate GPU checkpoint/restore and
measure backend performance.

`cuda_fork00` checks a process forked after CUDA started across checkpoint and
restore, and `cuda_fork01` that a forked process holding NVIDIA state of its
own is refused:

```
sudo ./test/zdtm.py run -t zdtm/static/cuda_fork00 -t zdtm/static/cuda_fork01 --cuda-checkpoint
```

# Known Limitations
* Currently GPU memory contents are brought into main system memory and CRIU
  then checkpoints that as part of the normal procedure. On systems with many
  GPU's with high GPU memory usage this can cause memory thrashing. A future
  CUDA release will add support for dumping the memory contents to files to
  alleviate this as well as support in the CRIU plugin.
* There's currently a small race between when a PAUSE_DEVICES hook is called on
  a running process and a process calls cuInit() and finishes initializing CUDA
  after the PAUSE is issued but before the process is frozen to checkpoint. This
  will cause the CUDA Driver API to report that the process is in an illegal
  state for checkpointing and it's recommended to just attempt the CRIU procedure
  again, this should be very rare.
* Applications that use NVML will leave some leftover device references as NVML
  is not currently supported for checkpointing. There will be support for this
  in later drivers. A possible temporary workaround is to have the
  {DUMP,RESTORE}_EXT_FILE hook just ignore /dev/nvidiactl and /dev/nvidia{0..N}
  remaining references for these applications as in most cases NVML is used to
  get info such as gpu count and some capabilities and these values are never
  accessed again and unlikely to change.
* Restore without a device map requires compatible GPUs with the original
  UUIDs. A device map permits different UUIDs, but the target GPUs must still be
  compatible with the checkpoint and provide enough memory.
* NVIDIA UVM Managed Memory, MIG (Multi Instance GPU), and MPS (Multi-Process
  Service) are currently not supported for checkpointing. Future CUDA releases
  will add support for these.
