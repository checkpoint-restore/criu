Checkpoint and Restore for CUDA applications with CRIU
======================================================

# Requirements
The `cuda_plugin` build and install targets provide one CRIU plugin,
`cuda_plugin.so`. It contains two private checkpoint backends so the same CRIU
deployment can run on nodes with different NVIDIA driver versions:

* On r580 and newer drivers, the plugin uses the CUDA Driver API directly.
* On older supported drivers, such as r565 and r570, it invokes the
  `cuda-checkpoint` utility. That utility must be in `PATH` and must support the
  `--action` option.

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

The direct backend does not require CUDA toolkit headers at build time. The
`cuDriverGetVersion` threshold deliberately prevents it from using the mirrored
CUDA 13.0 restore ABI on older drivers merely because checkpoint symbols are
present.

During checkpoint and restore, the Driver API backend calls libcuda directly
on CRIU's tracing thread. A temporary SIGCHLD handler watches the CUDA restore
thread. Any unexpected ptrace stop or exit aborts the operation with
siglongjmp(), without forwarding the signal or waiting for libcuda to return.
After a successful call, CRIU interrupts the restore thread again and waits
for its stop with a finite internal budget, independent of
`cuda_plugin.timeout`. Once the thread stops, CRIU restores its signal mask and
ptrace options. The original SIGCHLD handler and signal mask are restored on
both success and failure; unrelated child events remain available to CRIU.

This is a best-effort escape from a fatal target failure. A jump can bypass
locks held inside libcuda or libc. The plugin skips further CUDA calls and
does not close libcuda after abandoning a call, but CRIU's remaining error
cleanup can still encounter an abandoned libc lock. The guard does not impose
a deadline on a libcuda hang without a restore-thread stop or exit.

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
After a fatal helper or
restore-thread failure, the plugin skips further CUDA operations during
rollback. Terminating a helper does not establish that CUDA state was rolled
back: GPU state may remain locked or partially checkpointed, and the application
may need to be restarted. The plugin cannot recover a CUDA job after a fatal
driver fault.

The plugin contains independently authored declarations for the CUDA checkpoint
argument structures because CRIU does not build against the CUDA toolkit
headers. These declarations describe the ABI used by the plugin; they are not a
general-purpose CUDA header. Reserved fields are zeroed and must not be
repurposed without an explicit driver-version check and verification of the
corresponding CUDA release.

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
plugin will re-wake when needed.

# Testing

The CPU-only regression tests exercise both backends with mock CUDA APIs and
real ptrace stops, including separate restore threads in multithreaded targets,
aborted Driver API calls, completion races, SIGCHLD delivery to other tracer
threads, unrelated child events, unlimited and finite CLI waits, helper exits,
bounded post-call stop waits, and rollback:

```
make cuda_plugin
make -C test/cuda-checkpoint test
sudo python3 test/cuda-checkpoint/backend-errors.py
```

Real CUDA workloads are still needed to validate GPU checkpoint/restore and
measure backend performance.

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
* CUDA applications that fork() but don't call exec() but also don't issue any
  CUDA API calls will have some leftover references to /dev/nvidia* and fail to
  checkpoint as a result. This can be worked around in a similar fashion to the
  NVML case where the leftover references can be ignored as CUDA is not fork()
  safe anyway.
* Restore currently requires that you restore on a system with similar GPU's and
  same GPU count.
* NVIDIA UVM Managed Memory, MIG (Multi Instance GPU), and MPS (Multi-Process
  Service) are currently not supported for checkpointing. Future CUDA releases
  will add support for these.
