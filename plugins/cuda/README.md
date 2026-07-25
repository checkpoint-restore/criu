Checkpoint and Restore for CUDA applications with CRIU
======================================================

# Requirements
The NVIDIA CUDA driver library, `libcuda.so.1`, must be available at runtime and
an r570 or higher GPU driver is required for CUDA CRIU integration support.

## CUDA Driver API
The CUDA plugin loads `libcuda.so.1` dynamically and uses the CUDA checkpoint
Driver API symbols:

* `cuInit`
* `cuCheckpointProcessLock`
* `cuCheckpointProcessCheckpoint`
* `cuCheckpointProcessRestore`
* `cuCheckpointProcessUnlock`
* `cuCheckpointProcessGetState`
* `cuCheckpointProcessGetRestoreThreadId`

The plugin does not require the `cuda-checkpoint` utility or CUDA toolkit
headers at build time. Updating the NVIDIA driver is enough to get newer
checkpoint API behavior.

The plugin contains independently authored declarations for the CUDA checkpoint
argument structures because CRIU does not build against the CUDA toolkit
headers. These declarations describe the ABI used by the plugin; they are not a
general-purpose CUDA header. Reserved fields are zeroed and must not be
repurposed without an explicit driver-version check and verification of the
corresponding CUDA release.

# Checkpointing Procedure
The CUDA Driver API exposes 4 actions used in the checkpointing process: lock,
checkpoint, restore, unlock.

* lock - Used with the PAUSE_DEVICES hook while a process is still running to
  quiesce the application into a state where it can be checkpointed
* checkpoint - Used with the CHECKPOINT_DEVICES hook once a process has been
  seized/frozen to perform the actual checkpointing operation
* restore/unlock - Used with the RESUME_DEVICES_LATE hook to restore the CUDA
  state and release the process back to it's running state

## GPU device mapping

During a dump, the v2 plugin saves the ordinal and UUID of every CUDA GPU in
the `cuda-gpu-inventory.img` plugin image. During restore, the v2 plugin
accepts mappings through CRIU's `cuda.device-map` plugin option. A device map
is optional. Without one, CUDA uses the original UUIDs from the checkpoint.
When a map is supplied, it must specify every GPU in the checkpoint.

The UUID form is compatible with the `cuda-checkpoint` tool. This example
swaps the first two GPUs and leaves the rest unchanged; the list must be
extended to include all GPUs in the checkpoint:

```bash
i=0
for uuid in $(nvidia-smi --list-gpus | grep -oP 'UUID: \K[^)]+'); do
    export GPU_$i=$uuid
    i=$((i+1))
done

criu restore ... --plugin-option \
  "cuda.device-map=$GPU_0=$GPU_1,$GPU_1=$GPU_0,$GPU_2=$GPU_2,$GPU_3=$GPU_3"
```

The saved inventory also allows ordinal mappings, so the old UUIDs do not need
to be copied from the dump host. The left ordinal is the GPU ordinal at dump
time and the right ordinal is the GPU ordinal on the restore host:

```bash
criu restore ... --plugin-option \
  "cuda.device-map=0=1,1=0,2=2,3=3"
```

`cuda.device-map=auto` maps each checkpoint GPU to the destination GPU with the
same ordinal:

```bash
criu restore ... --plugin-option cuda.device-map=auto
```

This differs from omitting the option. Omitting it keeps the original UUIDs;
`auto` allows the destination UUIDs to differ while preserving the ordinal
order.

The v2 plugin passes the resolved `CUcheckpointGpuPair` array to the CUDA
Driver API. Every map requires a driver with GPU device-map support. Numeric
mappings and `auto` also require the saved inventory.

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
* Restore without a device map requires a system with similar GPUs and the same
  GPU count. A device map can remap checkpointed GPU UUIDs to restore-host GPU
  UUIDs, but the target GPUs must still be compatible with the checkpoint.
* NVIDIA UVM Managed Memory, MIG (Multi Instance GPU), and MPS (Multi-Process
  Service) are currently not supported for checkpointing. Future CUDA releases
  will add support for these.
