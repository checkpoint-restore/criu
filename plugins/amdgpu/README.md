Supporting ROCm with CRIU
=========================

_Felix Kuehling <Felix.Kuehling@amd.com>_<br>
_Rajneesh Bardwaj <Rajneesh.Bhardwaj@amd.com>_<br>
_David Yat Sin <David.YatSin@amd.com>_

# Introduction

ROCm is the Radeon Open Compute Platform developed by AMD to support
high-performance computing and machine learning on AMD GPUs. It is a nearly
fully open-source software stack starting from the kernel mode GPU driver,
including compilers and language runtimes, all the way up to optimized
mathematics libraries, machine learning frameworks and communication libraries.

Documentation for the ROCm platform can be found here:
https://rocmdocs.amd.com/en/latest/

CRIU is a tool for freezing and checkpointing running applications or
containers and later restoring them on the same or a different system. The
process is transparent to the application being checkpointed. It is mostly
implemented in user mode and relies heavily on Linux kernel features, e.g.
cgroups, ptrace, vmsplice, and more. It can checkpoint and restore most
applications relying on standard libraries. However, it is not able to
checkpoint and restore applications using device drivers, with their own
per-application kernel mode state, out of the box. This includes ROCm
applications using the KFD device driver to access GPU hardware resources. CRIU
includes some plugin hooks to allow extending it to add such support in the
future.

A common environment for ROCm applications is in data centers and compute
clusters. In this environment, migrating applications using CRIU would be
beneficial and desirable. This paper outlines AMDs plans for adding ROCm
support to CRIU.

# State associated with ROCm applications

ROCm applications communicate with the kernel mode driver “amdgpu.ko” through
the Thunk library “libhsakmt.so” to enumerate available GPUs, manage
GPU-accessible memory, user mode queues for submitting work to the GPUs, and
events for synchronizing with GPUs. Many of those APIs create and manipulate
state maintained in the kernel mode driver that would need to be saved and
restored by CRIU.

## Memory

ROCm manages memory in the form of buffer objects (BOs). We are also working on
a new memory management API that will be based on virtual address ranges. For
now, we are focusing on the buffer-object based memory management.

There are different types of buffer objects supported:

* VRAM (device memory managed by the kernel mode driver)
* GTT (system memory managed by the kernel mode driver)
* Userptr (normal system memory managed by user mode driver or application)
* Doorbell (special aperture for sending signals to the GPU for user mode command submissions)
* MMIO (special aperture for accessing GPU control registers, used for certain cache flushing operations)

All these BOs are typically mapped into the GPU page tables for access by GPUs.
Most of them are also mapped for CPU access. The following BO properties need
to be saved and restored for CRIU to work with ROCm applications:

* Buffer type
* Buffer handle
* Buffer size (page aligned)
* Virtual address for GPU mapping (page aligned)
* Device file offset for CPU mapping (for VRAM and GTT BOs)
* Memory contents (for VRAM and GTT BOs)

## Queues

ROCm uses user mode queues to submit work to the GPUs. There are several memory
buffers associated with queues. At the language runtime or application level,
they expose the ring buffer as well as a signal object to tell the GPU about
new commands added to the queue. The signal is mapped to a doorbell (a 64-bit
entry in the doorbell aperture mapped by the doorbell BO). Internally there are
other buffers needed for dispatch completion tracking, shader state saving
during queue preemption and the queue state itself. Some of these buffers are
managed in user mode, others are managed in kernel mode.

When an application is checkpointed, we need to preempt all user mode queues
belonging to the process, and then save their state, including:

* Queue type (compute or DMA)
* MQD (memory queue descriptor managed in kernel mode), with state such as
  * ring buffer address
  * read and write pointers
  * doorbell offset
  * pointer to AQL queue data structure
* Control stack (kernel-managed piece of state needed for resuming preempted queue)

The rest of the queue state is contained in user-managed buffer objects that
will be saved by the memory state handling described above:

* Ring buffer (userptr BO containing commands sent to the GPU)
* AQL queue data structure (userptr BO containing `struct hsa_queue_t`)
* EOP buffer (VRAM BO used for dispatch completion tracking by the command processor)
* Context save area (userptr BO for saving shader state of preempted wavefronts)

## Events

Events are used to implement interrupt-based sleeping/waiting for signals sent
from the GPU to the host. Signals are represented by some data structures in
KFD and an entry in a user-allocated, GPU-accessible BO with event slots. We
need to save the allocated set of event IDs and each event’s signaling state.
The contents of the event slots will be saved by the memory state handling
described above.

## Topology

When ROCm applications are started, they enumerate the device topology to find
available GPUs, their capabilities and connectivity. An application can be
checkpointed at any time, so it will not be at a safe place to re-enumerate the
topology when it is restored. Therefore, we can only support restoring
applications on systems with a very similar topology:

* Same number of GPUs
* Same type of GPUs (i.e. instruction set, cache sizes, number of compute units, etc.)
* Same or larger memory size
* Same VRAM accessibility by the host
* Same connectivity and P2P memory support between GPUs

At the KFD ioctl level, GPUs are identified by GPUIDs, which are unique
identifiers created by hashing various GPU properties. That way a GPUID will
not change during the lifetime of a process, even in a future where GPUs may be
added or removed dynamically. When restoring a process on a different system,
the GPUID may have changed. Or it may be desirable to restore a process using a
different subset of GPUs on the same system (using cgroups). Therefore, we will
need a translation of GPUIDs for restored processes that applies to all KFD
ioctl calls after an application was restored.

# CRIU plugins

CRIU provides plugin hooks for device files:

    int cr_plugin_dump_file(int fd, int id);
    int cr_plugin_restore_file(int id);

In a ROCm process, it will be invoked for `/dev/kfd` and `/dev/dri/renderD*`
device nodes. `/dev/kfd` is used for KFD ioctl calls to manage memory, queues,
signals and other functionality for all GPUs through a single device file
descriptor. `/dev/dri/renderD*` are per GPU device files, called render nodes,
that are used mostly for CPU mapping of VRAM and GTT BOs. Each BO is given a
unique offset in the render node of the corresponding GPU at allocation time.

Render nodes are also used for memory management and command submission by the
Mesa user mode driver for video decoding and post processing. These use cases
are relevant even in data centers. Support for this is not an immediate
priority but planned for the future. This will require saving additional state
as well as synchronization with any outstanding jobs. For now, there is no
kernel-mode state associated with `/dev/renderD*`.

The two existing plugins can be used for saving and restoring most state
associated with ROCm applications. We are planning to add new ioctl calls to
`/dev/kfd` to help with this.

## Dumping

At the “dump” stage, the ioctl will execute in the context of the CRIU dumper
process. But the file descriptor (fd) is “drained” from the process being saved
by the parasite code that CRIU injects into its target. This allows the plugin
to make an ioctl call with enough context to allow KFD to access all the kernel
mode state associated with the target process. CRIU is ptrace attached to the
target process. KFD can use that fact to authorize access to the target
process' information.

The contents of GTT and VRAM BOs are not automatically saved by CRIU. CRIU can
only support saving the contents of normal pageable mappings. GTT and VRAM BOs
are special device file IO mappings. Therefore, our dumper plugin will need to
save the contents of these BOs. In the initial implementation they can be
accessed through `/proc/<pid>/mem`. For better performance we can use a DMA
engine in the GPU to copy the data to system memory.

## Restoring

At the “restore” stage we first need to ensure that the topology of visible
devices (in the cgroup) is compatible with the topology that was saved. Once
this is confirmed, we can use a new ioctl to load the saved state back into
KFD. This ioctl will run in the context of the process being restored, so no
special authorization is needed. However, some of the data being copied back
into kernel mode could have been tampered with. MQDs and control stacks provide
access to privileged GPU registers. Therefore, the restore ioctl will only be
allowed to run with root privileges.

## Remapping render nodes and mmap offsets

BOs are mapped for CPU access by mmapping the GPU's render node at a specific
offset. The offset within the render node device file identifies the BO.
However, when we recreate the BOs, we cannot guarantee that they will be
restored with the same mmap offset that was saved, because the mmap offset
address space per device is shared system wide.

When a process is restored on a different GPU, it will need to map the BOs from
a different render node device file altogether.

A new plugin call will be needed to translate device file names and mmap
offsets to the newly allocated ones, before CRIU's PIE code restores the VMA
mappings. Fortunately, ROCm user mode does not remember the file names and mmap
offsets after establishing the mappings, so changing the device files and mmap
offsets under the hood will not be noticed by ROCm user mode.

*This new plugin is enabled by the new hook `__UPDATE_VMA_MAP` in our RFC patch
series.*

## Resuming GPU execution

At the time of running the `cr_plugin_restore_file` plugin, it is too early to
restore userptr GPU page table mappings and their MMU notifiers. These mappings
mirror CPU page tables into GPU page tables using the HMM mirror API in the
kernel. The MMU notifiers notify the driver when the virtual address mapping
changes so that the GPU mapping can be updated.

This needs to happen after the restorer PIE code has restored all the VMAs at
their correct virtual addresses. Otherwise, the HMM mirroring will simply fail.
Before all the GPU memory mappings are in place, it is also too early to resume
the user mode queue execution on the GPUs.

Therefore, a new plugin is needed that runs in the context of the master
restore process after the restorer PIE code has restored all the VMAs and
returned control to all the restored processes via sigreturn. It needs to be
called once for each restored target process to finalize userptr mappings and
to resume execution on the GPUs.

*This new plugin is enabled by the new hook `__RESUME_DEVICES_LATE` in our RFC
patch series.*

## Other CRIU changes

In addition to the new plugins, we need to make some changes to CRIU itself to
support device file VMAs. Currently CRIU will simply fail to dump a process
that has such PFN or IO memory mappings. While CRIU will not need to save the
contents of those VMAs, we do need CRIU to save and restore the VMAs
themselves, with translated mmap offsets (see “Remapping mmap offsets” above).

## Security considerations

The new “dump” ioctl we are adding to `/dev/kfd` will expose information about
remote processes. This is a potential security threat. CRIU will be
ptrace-attached to the target process, which gives it full access to the state
of the process being dumped. KFD can use ptrace attachment to authorize the use
of the new ioctl on a specific target process.

The new “restore” ioctl will load privileged information from user mode back
into the kernel driver and the hardware. This includes MQD contents, which will
eventually be loaded into HQD registers, as well as a control stack, which is a
series of low-level commands that will be executed by the command processor.
Therefore, we are limiting this ioctl to the root user. If CRIU restore must be
possible for non-root users, we need to sanitize the privileged state to ensure
it cannot be used to circumvent system security policies (e.g. arbitrary code
execution in privileged contexts with access to page tables etc.).

Modified mmap offsets could potentially be used to access BOs belonging to
different processes. This potential threat is not new with CRIU. `amdgpu.ko`
already implements checking of mmap offsets to ensure a context (represented by
a render node file descriptor) is only allowed access to its own BOs.

# Glossary

Term | Definition
--- | ---
CRIU | Checkpoint/Restore In Userspace
ROCm | Radeon Open Compute Platform
Thunk | User-mode API interface  to interact with amdgpu.ko
KFD | AMD Kernel Fusion Driver
Mesa | Open source OpenGL implementation
GTT | Graphics Translation Table, also used to denote kernel-managed system memory for GPU access
VRAM | Video RAM
BO | Buffer Object
HMM | Heterogeneous Memory Management
AQL | Architected Queueing Language
EOP | End of pipe (event indicating shader dispatch completion)
MQD | Memory Queue Descriptors
HQD | Hardware Queue Descriptors
PIE | Position Independent Executable
