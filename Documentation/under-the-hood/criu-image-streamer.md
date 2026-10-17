# Image Streamer

`criu-image-streamer` is an external companion daemon (written in Rust) that streams checkpoint and restore images through UNIX pipes and file descriptors. By connecting directly to CRIU via a UNIX domain socket, it enables image data to be piped to remote storage, compression tools, or network endpoints without buffering image files on local disk.

## The Problem

By default, CRIU requires a local filesystem directory (`-D <dir>`) where it writes images during dump and reads them during restore. In virtualized and cloud environments, this introduces significant bottlenecks:

* **Double I/O on Network Disks**: Cloud VM volumes (such as AWS EBS or GCP Persistent Disk) are network-attached. Dumping to disk and subsequently uploading to object storage writes image data over the network twice, consuming disk bandwidth and doubling transfer times.
* **Storage Allocation**: The local filesystem must allocate enough free disk space to store the full memory dump of the running process tree.
* **Tight Eviction Windows**: Spot instances and preemptible VMs receive short termination notices (typically 30 to 120 seconds). Performing a full local dump followed by a separate upload often exceeds this window before the VM is reclaimed.

## Architecture and Implementation

`criu-image-streamer` integrates with CRIU through a streaming protocol enabled by CRIU's `--stream` option (introduced in CRIU 3.15).

### UNIX Socket and Zero-Copy Pipeline (`splice`)
1. When started in `capture` or `serve` mode, the streamer creates a dedicated UNIX domain socket inside `--images-dir`:
   * `streamer-capture.sock` during checkpoint (`O_DUMP`).
   * `streamer-serve.sock` during restoration (`O_RSTR`).
2. CRIU connects to this socket when invoked with `--stream`. Instead of creating image files on disk, CRIU sends requests for individual image streams.
3. CRIU and the streamer exchange pipe file descriptors over the socket using `SCM_RIGHTS`.
4. During capture, the streamer uses the Linux `splice()` system call to transfer pages pipe-to-pipe without copying data through userspace buffers. This zero-copy path achieves an overhead of approximately 0.1 CPUsec/GB during dump. During restore, images are buffered in memory and fed to CRIU pipes.


## Comparison: Streamer vs. Live Migration vs. Lazy Pager

CRIU provides three distinct mechanisms for transferring process state across machines, each optimized for different operational trade-offs:

| Property | Live Migration (P.Haul) | Lazy Pager (`userfaultfd`) | Image Streamer |
| :--- | :--- | :--- | :--- |
| **Strategy** | Pre-copy | Post-copy | Direct streaming |
| **When memory moves** | Iteratively before process freeze | On demand after restore | In a single pass during freeze |
| **Process downtime** | Lowest (~tens of ms) under light writes | Near zero | Proportional to memory size / network speed |
| **Source host dependency** | Needed until final sync | Needed until all pages are fetched | Can be terminated immediately after dump |
| **High write-rate workloads** | Pre-copy aborts after 8 iterations or 10% grow rate, forcing a large final dump | High page-fault latency spikes | Predictable single-pass transfer time |
| **Non-memory metadata** | Written locally, then synced over socket | Written to local image directory on disk | Streamed through pipes (zero local disk) |
| **Data destination** | Live destination host daemon | Live destination host daemon | File descriptors, stdout, or remote pipes |
| **Local disk requirement** | Required for intermediate images | Required for non-memory images | None (bypasses local disk entirely) |

### Key Trade-offs

* **vs. Live Migration (P.Haul)**: Live migration minimizes application downtime by iteratively copying dirty memory pages while the workload continues running. If the workload dirties memory faster than the network can transmit it, P.Haul limits iterations (maximum 8 rounds, or if dirty pages grow by >10%) and forces a final stop-the-world dump, which spikes downtime. In contrast, the image streamer freezes the workload upfront and streams memory at full network line rate, ensuring completion in a single deterministic pass.
* **vs. Lazy Pager (`userfaultfd`)**: Lazy migration resumes the process on the destination host immediately with empty memory, resolving missing pages via `userfaultfd` page-fault events across the network. This requires the source host to stay alive and reachable for the entire lifecycle of the transfer. Non-memory metadata files must still be placed on local disk. With `criu-image-streamer`, the source host can be shut down as soon as the dump finishes.

## Basic Usage

CLI options must be passed **before** the subcommand (`capture`, `serve`, or `extract`).

### Checkpoint with Compression
```bash
# Start the streamer in capture mode, piping stdout to a compressor
criu-image-streamer --images-dir /tmp/imgdir capture | lz4 -f - /tmp/img.lz4 &

# Dump the process using the streamer socket directory
criu dump --images-dir /tmp/imgdir --stream --shell-job --tree <PID>
```

### Restore
```bash
# Decompress and feed the stream to the streamer in serve mode
lz4 -d /tmp/img.lz4 - | criu-image-streamer --images-dir /tmp/imgdir serve &

# Restore the process from the streamer socket directory
criu restore --images-dir /tmp/imgdir --stream --shell-job
```

## Use Cases

* **Preemptible / Spot VM Eviction**: Evacuating state directly through streaming pipelines upon receiving an instance termination notice.
* **Diskless / Read-Only Environments**: Running CRIU on hosts without writable local disks or with restricted storage quotas.
* **Decoupled Migration**: Checkpointing a workload when the destination host is not yet provisioned or known.

## See Also

* [Userfaultfd and Lazy Migration](userfaultfd.md)
* [Memory Dumping and Restoring](memory-dumping-and-restoring.md)
* [Optimizing Pre-dump Algorithm](optimizing-pre-dump-algorithm.md)
* [P.Haul Documentation](https://criu.org/P.Haul)
* [criu-image-streamer Repository](https://github.com/checkpoint-restore/criu-image-streamer)
