# CRIU: Under the Hood

This directory contains technical documentation detailing the internal implementation of CRIU, the kernel APIs it leverages, and the complex algorithms used to achieve checkpoint and restore of various Linux resources.

## Core Architecture & Lifecycle

* [Checkpoint and Restore Overview](checkpointrestore.md): High-level view of the C/R process.
* [Freezing the Process Tree](freezing-the-tree.md): How CRIU stops the application using the freezer cgroup or signals.
* [Parasite Code](parasite-code.md): Injection and execution of code within the victim's address space.
* [Restorer Context](restorer-context.md): The environment in which the restorer blob executes.
* [Stages of Restore](stages-of-restoring.md): Detailed breakdown of the multi-stage restoration process.
* [Final States](final-states.md): The state of processes after restore.
* [Technologies Used](technologies.md): Overview of kernel technologies CRIU depends on.
* [Kerndat](kerndat.md): How CRIU probes and caches kernel feature support.
* [Plugins](plugins.md): Extending CRIU for external resources

## Memory Management

* [Memory Dumping and Restoring](memory-dumping-and-restoring.md): The primary algorithms for memory C/R.
* [Memory Changes Tracking](memory-changes-tracking.md): Using dirty bits (soft-dirty) for iterative migration.
* [Pagemap Cache](pagemap-cache.md): Optimizing access to `/proc/pid/pagemap`.
* [Copy-on-Write Memory](copy-on-write-memory.md): Handling shared and private COW mappings.
* [Shared Memory](shared-memory.md): Restoration of SysV IPC and POSIX shared memory.
* [Memory Images Deduplication](memory-images-deduplication.md): Saving space in image files.
* [Optimizing Pre-dump Algorithm](optimizing-pre-dump-algorithm.md): Strategies for minimizing downtime.
* [Userfaultfd](userfaultfd.md): Lazy migration and post-copy restoration.

## Files, Mounts & I/O

* [Dumping Files](dumping-files.md): General overview of file descriptor C/R.
* [How hard is it to open a file?](how-hard-is-it-to-open-a-file.md): The complexities of reconstructing file states.
* [How to open a file without open() syscall](how-to-open-a-file-without-open-system-call.md): Using `linkat` and other tricks for inaccessible files.
* [How to assign needed FD to a file](how-to-assign-needed-file-descriptor-to-a-file.md): Re-mapping FDs to match original values.
* [Invisible Files](invisible-files.md): Handling unlinked but open files.
* [FD Info Engine](fdinfo-engine.md): Parsing `/proc/pid/fdinfo`.
* [Service Descriptors](service-descriptors.md): Managing CRIU's internal FDs to avoid collisions.
* [Mount Points](mount-points.md): Basic mount restoration.
* [Mount V2](mount-v2.md): Modern mount restoration using `open_tree` and `move_mount`.
* [Mounts V2 Virtuozzo](mounts-v2-virtuozzo.md): Extensions for Virtuozzo-specific mount features.
* [Filesystem Peculiarities](filesystems-pecularities.md): Handling `/dev`, `/proc`, `sysfs`, etc.
* [IRM](irmap.md): Inode-to-path mapping (irmap).
* [KCMP Trees](kcmp-trees.md): Using `kcmp` to deduplicate shared resources.
* [Validate Files on Restore](validate-files-on-restore.md): Ensuring file consistency.
* [FSNotify](fsnotify.md): Checkpointing inotify and fanotify marks.
* [AIO](aio.md): Checkpointing asynchronous I/O contexts.

## Networking

* [TCP Connections](tcp-connection.md): Using TCP Repair mode for zero-loss socket migration.
* [Unix Sockets](unix-sockets.md): Reconnecting stream and dgram unix sockets.
* [Sockets](sockets.md): General socket restoration (Netlink, Raw, etc.).
* [Change IP Address](change-ip-address.md): Handling network configuration changes during migration.
* [MAC-VLAN](mac-vlan.md): Support for MAC-VLAN interfaces.
* [TUN/TAP](tun-tap.md): Virtual network device restoration.

## Process & Resource Management

* [PID Restore](pid-restore.md): Algorithms for restoring tasks with specific PIDs.
* [PIDFD](pidfd.md): Checkpointing and restoring pidfds.
* [PIDFD Store](pidfd-store.md): Internal management of pidfds.
* [Zombies](zombies.md): Handling processes in the `EXIT_ZOMBIE` state.
* [32-bit Tasks C/R](32bit-tasks-cr.md): Specifics for IA32/compat mode tasks.
* [Pending Signals](pending-signals.md): Capturing and re-queuing signals.
* [Restartable Sequences (rseq)](restartable-sequences.md): Handling the `rseq` kernel feature.
* [vDSO](vdso.md): Handling the virtual dynamic shared object across kernel versions.
* [TTYs](ttys.md): The complex state of terminal devices and PTY pairs.
* [CGroups](cgroups.md): Restoring cgroup hierarchy and membership.

## Security & Kernel Features

* [AppArmor](apparmor.md): Handling AppArmor profiles during dump and restore.
* [ARM64 GCS](arm64-gcs.md): Guarded Control Stack support on AArch64.
* [BPF Maps](bpf-maps.md): Experimental support for checkpointing BPF map data.
* [Code Blobs](code-blobs.md): Management of PIE blobs (parasite, restorer).

## Comparison & External Tools

* [Comparison to other C/R projects](comparison-to-other-cr-projects.md): How CRIU differs from DMTCP, BLCR, etc.
* [DMTCP](dmtcp.md): Specific notes on DMTCP integration or comparison.
* [FAQ](faq.md): Frequently Asked Questions about CRIU internals.

---
*Generated by Gemini CLI as part of the Documentation Audit (March 2026).*
