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

The direct backend does not require CUDA toolkit headers at build time. The
`cuDriverGetVersion` threshold deliberately prevents it from using the mirrored
CUDA 13.0 restore ABI on older drivers merely because checkpoint symbols are
present.

The plugin contains independently authored declarations for the CUDA checkpoint
argument structures because CRIU does not build against the CUDA toolkit
headers. These declarations describe the ABI used by the plugin; they are not a
general-purpose CUDA header. Reserved fields are zeroed and must not be
repurposed without an explicit driver-version check and verification of the
corresponding CUDA release.

## GPU device mapping

During a CUDA dump, the plugin saves the ordinal and UUID of each GPU in the
plugin-private `cuda-gpu-inventory.img` image. During restore, an optional
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
UUIDs to change while preserving ordinal order. Every supplied map must cover
each checkpoint GPU exactly once. Images without the private GPU inventory are
compatible with explicit UUID-to-UUID maps, but cannot use ordinals or `auto`.

The common mapping code resolves every form to UUID pairs. The Driver API
backend passes those pairs in `CUcheckpointRestoreArgs`; the CLI backend formats
the same pairs for `cuda-checkpoint --device-map`. This keeps the inventory and
mapping semantics independent of which backend performed dump or restore.

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
plugin will re-wake when needed.

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
* Restore without a device map requires compatible GPUs with the original
  UUIDs. A device map permits different UUIDs, but the target GPUs must still be
  compatible with the checkpoint and provide enough memory.
* NVIDIA UVM Managed Memory, MIG (Multi Instance GPU), and MPS (Multi-Process
  Service) are currently not supported for checkpointing. Future CUDA releases
  will add support for these.
