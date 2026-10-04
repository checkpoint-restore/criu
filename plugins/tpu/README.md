Checkpoint and Restore for TPU applications with CRIU
======================================================

# Requirements
The tpucheckpoint utility should be placed somewhere in your $PATH, and the
workload's TPU runtime must support the tpu_control checkpoint/restore
protocol. The plugin detects support by the presence of the libtpu control
thread in the workload process.

## tpucheckpoint
The tpucheckpoint utility lives in the gVisor tree:
https://github.com/google/gvisor/tree/master/tools/tpucheckpoint

tpucheckpoint is a binary utility used to issue checkpointing commands to
TPU applications. It speaks the libtpu control protocol
(pkg/sentry/control/tpu_control.proto in gVisor): libtpu spawns a control
thread named "libtpu{XXXXYYYY}" in the workload process, where the
8-character hex suffix encodes the request/response pipe FD numbers, and
tpucheckpoint discovers this thread via /proc and exchanges
length-delimited protobuf messages over the pipes.

# Checkpointing Procedure
tpucheckpoint exposes 2 actions used in the checkpointing process:
checkpoint, restore.

* checkpoint - Used with the CHECKPOINT_DEVICES hook once a process has been
  seized/frozen to perform the actual checkpointing operation. libtpu moves
  the HBM contents of all attached TPU chips into buffers in the process's
  host memory and closes its TPU device file descriptors, so CRIU's normal
  memory dump captures the device state and no TPU device files remain open
  at dump time.
* restore - Used with the RESUME_DEVICES_LATE hook to reattach the TPU
  devices and copy the HBM contents back.

These actions are serviced by the libtpu control thread inside the target
process, which the TPU plugin resumes when needed while the rest of the
process stays frozen.

# Known Limitations
* The PAUSE_DEVICES hook does not quiesce the device: it does not gate new
  TPU work or drain in-flight programs the way the CUDA plugin's lock
  action does. The caller must guarantee the workload is TPU-idle before
  dumping. The tpu_control protocol defines a lock action, and this hook is
  the natural place to invoke it, mirroring the CUDA plugin.
* TPU memory contents are brought into main system memory and CRIU then
  checkpoints that as part of the normal procedure. HBM capacity can be
  large (tens to hundreds of GiB per host), so ensure the host has enough
  free memory headroom for the dump.
* Restore requires a system with identical TPU topology (chip architecture,
  chip count, and interconnect mesh shape).
