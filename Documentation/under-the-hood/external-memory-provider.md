# External Memory Provider

The **external memory provider** is an optional helper process that hands
CRIU ready-to-use file descriptors instead of having CRIU read and copy
checkpoint data itself. On restore it supplies the contents of image files and
the backing memory of private anonymous VMAs, shared anonymous memory and
memfds. On dump it can accept image files.

The goal is fast restore of applications with large memory footprints, such as
GPU inference workloads. A provider can download or read the checkpoint from
any storage backend in parallel and place it straight into memfds, possibly
before CRIU even starts. CRIU then only maps those memfds. It does not copy the
page data again.

CRIU knows nothing about the storage backend. It requests objects by name or by
identity, and the provider returns one file descriptor per object over a Unix
socket.

## Why the existing paths do not fit

* **Page images, page-server and `page_xfer`** move bytes through pipes with
  `vmsplice()`/`splice()` or over TCP. Every page is still copied into the
  restored address space, and the transfer is serialized through the pipe.
* **Lazy pages (userfaultfd)** install pages on demand. For anonymous private
  memory this requires `UFFDIO_COPY`, which copies data that is already
  materialized. `UFFDIO_CONTINUE` cannot be used on anonymous private
  mappings.
* **criu-image-streamer** streams image bytes over a pipe. CRIU still copies
  them into memory, and the streamer must reassemble the whole stream before it
  can serve the images CRIU reads first.

The provider relies only on existing kernel primitives: memfd, `mmap()` and
`SCM_RIGHTS`.

## Enabling the provider

The launcher creates a connected Unix `SOCK_SEQPACKET` socket pair, keeps one
end for the provider and passes the other end to CRIU as the inherited-FD
resource named `extmem-provider`:

```
criu restore -D imgs --inherit-fd 'fd[4]:extmem-provider' ...
criu dump    -D imgs --inherit-fd 'fd[4]:extmem-provider' ...
```

Through RPC, the same descriptor is passed in the `inherit_fd` list of the
request. RPC supports this only in `criu swrk` mode. `extmem-provider` is a
reserved key: it does not match any file in the images.

If no `extmem-provider` descriptor is given, CRIU behaves exactly as before.

One connection serves one session (one dump or one restore). CRIU keeps the
socket as a service descriptor. Restored tasks close their copies before
entering the restorer blob, so the socket is never visible to the restored
application. The main CRIU process closes the socket after it sends `COMMIT`
or `ABORT`.

## Wire protocol

### Framing

* Each request is one `extmem_req` protobuf message in one `SOCK_SEQPACKET`
  packet. Each response is one `extmem_resp` message in one packet.
* Requests and responses must each fit into 8 KiB.
* A successful `OPEN_IMAGE`, `GET_VMA` or `GET_SHARED` response carries exactly
  one file descriptor in an `SCM_RIGHTS` control message. All other responses,
  including errors, must not carry any ancillary data. CRIU treats a missing,
  extra or unexpected descriptor, or a truncated packet, as a protocol error.
* Exactly one request is outstanding at a time. Several restored tasks share
  the socket, and CRIU serializes their request/response pairs with a lock
  shared between the tasks. The provider must reply to every request, in
  order.
* CRIU has no timeout on the socket. A provider that stops responding blocks
  the dump or restore.
* A provider must treat EOF before `COMMIT` as `ABORT`. CRIU closes the
  socket without sending `ABORT` when a reply may still be pending, for
  example when a restored task is killed in the middle of a request. It also
  happens when CRIU itself crashes.

The schema is [`images/extmem.proto`](../../images/extmem.proto). It uses
proto2 and is MIT-licensed, so out-of-tree providers can use it under any
license:

```protobuf
enum extmem_op {
	EXTMEM_INIT = 1;
	EXTMEM_OPEN_IMAGE = 2;
	EXTMEM_GET_VMA = 3;
	EXTMEM_GET_SHARED = 4;
	EXTMEM_COMMIT = 5;
	EXTMEM_ABORT = 6;
	EXTMEM_WAIT_READY = 7;
}

enum extmem_mode {
	EXTMEM_MODE_DUMP = 1;
	EXTMEM_MODE_RESTORE = 2;
}

message extmem_init {
	required uint32 version = 1;
	required extmem_mode mode = 2;
	optional string images_dir = 3;
}

message extmem_open_image {
	required string name = 1;
	required uint32 flags = 2;
}

message extmem_get_vma {
	required uint32 pid = 1;
	required uint32 vma_id = 2;
	required uint64 vaddr = 3;
	required uint64 length = 4;
	required uint64 offset = 5;
}

message extmem_get_shared {
	required uint64 shmid = 1;
	required uint64 length = 2;
}

message extmem_req {
	required extmem_op op = 1;
	optional extmem_open_image open_image = 2;
	optional extmem_get_vma get_vma = 3;
	optional extmem_get_shared get_shared = 4;
	optional extmem_init init = 5;
}

message extmem_resp {
	required int32 status = 1;
}
```

The connection itself is the session; there is no session-ID field. New
optional fields can be added compatibly. A change that cannot be expressed as
a new field must become a new operation, or bump the protocol version.

### Session start (`INIT`)

`INIT` is the first request of every session and carries `extmem_init`:

| Field | Value |
|---|---|
| `version` | Protocol version spoken by CRIU, currently `1`. |
| `mode` | `EXTMEM_MODE_DUMP` for `criu dump`, `EXTMEM_MODE_RESTORE` for `criu restore`. |
| `images_dir` | Absolute path of the images directory as CRIU sees it (in CRIU's mount namespace). Optional: omitted if CRIU cannot resolve it. |

A provider that does not support the requested version or mode must reply
with an error. Replying `-ENOTSUP` makes CRIU continue without the provider.
Any other error fails the dump or restore.

### Operations

| Operation | Used in | Payload | Success reply |
|---|---|---|---|
| `INIT` | dump, restore | `init` | status 0 |
| `OPEN_IMAGE` | dump, restore | `open_image` | status 0 + FD |
| `GET_VMA` | restore | `get_vma` | status 0 + FD |
| `GET_SHARED` | restore | `get_shared` | status 0 + FD |
| `WAIT_READY` | restore | none | status 0 |
| `COMMIT` | dump, restore | none | status 0 |
| `ABORT` | dump, restore | none | status 0 |

### Status codes

`status` is `0` on success and a negative `errno` value otherwise. Both peers
run on the same node, so native errno numbers are used.

| Status | Meaning for CRIU |
|---|---|
| `0` | Success. |
| `-ENOTSUP` | The provider does not serve this object. CRIU uses its normal path for this object only. Returning it for `INIT` disables the provider for the whole session. |
| `-ENOENT` | For `OPEN_IMAGE` on restore: the image does not exist. CRIU handles it like a missing local image and does **not** fall back to the local directory. Fatal for other operations. |
| any other | Fatal: the dump or restore fails and CRIU sends `ABORT`. |

Positive values are treated as `-EIO`. A provider that accepted `INIT` must
implement `WAIT_READY`. CRIU treats `-ENOTSUP` for `WAIT_READY` as a protocol
error.

## Restore

### Sequence

```
CRIU                                          provider
 |  INIT  ------------------------------------>  |
 |  OPEN_IMAGE "pstree.img", ...  ------------>  |  (main process)
 |  GET_SHARED / OPEN_IMAGE ... -------------->  |  (restored tasks,
 |  GET_VMA (pid, vma_id, vaddr, ...) -------->  |   serialized)
 |  WAIT_READY  ------------------------------>  |
 |      apply saved memfd seals                  |
 |      run pre-resume action scripts            |
 |      resume tasks                             |
 |  COMMIT (or ABORT on failure)  ------------>  |
```

1. CRIU reads `inventory.img` from the local images directory. It then sends
   `INIT`, before it opens any other image.
2. Images, shared objects and private VMAs are requested as restore reaches
   them. Requests come from the main CRIU process and from the restored tasks.
   Each task requests its own private VMAs while it prepares its mappings,
   before it enters the restorer blob.
3. When every task has finished preparing its memory and files, which is the
   end of the `CR_STATE_RESTORE` stage, CRIU sends `WAIT_READY`. No more
   object requests follow. The provider must not reply until every object it
   has returned is fully populated.
4. CRIU applies the saved memfd seals, runs the `pre-resume` action scripts and
   resumes the tasks.
5. CRIU sends `COMMIT` once restore has completed successfully, or `ABORT` if
   it failed at any point. `COMMIT` is sent right after the tasks are
   resumed, before the `post-resume` action scripts run and before CRIU
   waits for the restored tree when it doesn't detach from it. The tasks are
   already running, so a `COMMIT` error is only logged and cannot undo the
   restore.

### Images (`OPEN_IMAGE`)

`name` is the image path relative to the images directory, e.g. `pstree.img`
or `pages-1.img`. `flags` contains the `open(2)` flags (`O_RDONLY` on
restore). The returned descriptor must be readable, seekable (CRIU reads page
images with `pread()`) and positioned at offset 0. It must be a new open file
description: never return the same open file twice, because CRIU relies on
the file offset. A memfd or a regular file on tmpfs works well.

These images are never offered to the provider and are always opened by CRIU:

* `inventory.img`, and any other image CRIU forces to be local;
* images from parent checkpoints, which are reached through the `parent`
  link created by `--prev-images-dir`. `OPEN_IMAGE` carries
  no checkpoint identity, so it cannot tell them apart from images with the
  same name in the current checkpoint;
* files opened outside the images directory, such as the stats file in the
  work directory.

### Private anonymous VMAs (`GET_VMA`)

| Field | Value |
|---|---|
| `pid` | PID of the task in its own PID namespace (the PID in `pstree.img`) |
| `vma_id` | 0-based index of the VMA in the `vmas` array of `mm-<pid>.img` |
| `vaddr` | VMA start address |
| `length` | VMA length in bytes |
| `offset` | File offset at which CRIU maps the returned FD (`VmaEntry.pgoff`, in bytes) |

`vma_id` is redundant with `vaddr`. A provider should check that both match
the image. Only VMAs that meet all of these conditions are offered:

* regular private anonymous mappings (`VMA_AREA_REGULAR | VMA_ANON_PRIVATE`),
  including private hugetlb mappings with a known huge-page size. Moving a
  provider-backed hugetlb mapping to its final address with `mremap()`
  requires Linux 5.16 or newer. Hugetlb VMAs that are not provider-backed
  are restored by the restorer as before;
* not vDSO, vvar, vsyscall, AIO ring, shadow stack, or plugin mappings;
* without `MAP_GROWSDOWN`, `MAP_DROPPABLE` or `MAP_LOCKED`, and without
  `MADV_WIPEONFORK`. A locked mapping is populated when it is mapped, before
  the provider has finished filling it.

The returned FD must contain the complete content of the VMA at the time of
the dump in the range `[offset, offset + length)`. `offset` is 0 for ordinary
anonymous memory. A private hugetlb mapping is backed by a hidden hugetlbfs
file in the kernel, so after it is split (e.g. by a partial `munmap()` or
`mprotect()`) a VMA can start at a non-zero file offset. CRIU maps the FD at
that offset, so that the restored VMA keeps it. Pages
that were never populated must read as zeros, which leaving holes in a memfd
does naturally. If the checkpoint was made on top of a pre-dump, the provider
is responsible for merging pages from the parent images. For hugetlb VMAs the
FD must be on hugetlbfs, e.g. a `MFD_HUGETLB` memfd, with the same huge-page
size.

CRIU maps the FD with `MAP_PRIVATE` in its temporary premap area. The restorer
blob later moves the mapping to `vaddr` and applies the saved protection and
madvise flags. CRIU still reads `pagemap-*.img` to walk the page layout, but it
skips the corresponding page data. CRIU does not check the type or size of the
FD.

If the provider returns `-ENOTSUP`, CRIU restores the VMA in the usual way.
When a parent task's VMA is provider-backed and the child's inherited copy of
it is not, the child gets its own copy of its saved pages and the
copy-on-write link between them is not restored. The same applies when both
are provider-backed but the provider returns different files.

Copy-on-write sharing between a parent and its forked children is therefore
not preserved for provider-backed VMAs. If many workers forked from one parent
share a large region, for example preloaded model weights, the restored tree
can use many times more memory than the original. A provider can keep the
sharing for VMAs whose contents are identical across tasks by returning the
same file for each of them.

### Shared memory and memfd (`GET_SHARED`)

| Field | Value |
|---|---|
| `shmid` | `VmaEntry.shmid` for shared anonymous memory; `MemfdInodeEntry.shmid` for a memfd |
| `length` | size of the object in bytes (`ShmemEntry` size or `MemfdInodeEntry.size`) |

The provider is asked once per object, not once per VMA. CRIU maps the
returned FD with `MAP_SHARED` into each VMA that references the object, at the
offset recorded for that VMA. For a memfd, the FD also becomes the restored
file descriptor of the application, so it must be a real memfd:

* sized to `length` (CRIU does not resize it);
* created with `MFD_ALLOW_SEALING` and carrying no seals. CRIU applies the
  saved seals with `F_ADD_SEALS` after `WAIT_READY`, and this fails if the
  memfd already has `F_SEAL_SEAL`;
* created with the same hugetlb flags as the original;
* ideally created with the saved name (`MemfdInodeEntry.name`). CRIU cannot
  rename it, and the name is visible in `/proc/PID/fd` and in later dumps.

CRIU restores the saved owner and mode of the memfd.

### Semantics of provider-backed private VMAs

A provider-backed private VMA is a `MAP_PRIVATE` mapping of a file, normally
a memfd, rather than an anonymous mapping. Reads see the memfd contents, and
the first write to a page creates a private copy-on-write page. Applications
can notice the difference:

* **`MADV_DONTNEED`** discards the private copies in the range. Later
  accesses fault the pages back in from the memfd: the application sees the
  **checkpointed content again, not zeros**. Only memfd holes read back as
  zeros. Allocators and runtimes that rely on `MADV_DONTNEED` zeroing
  anonymous memory may observe stale data.
* `MADV_FREE`, `MREMAP_DONTUNMAP` and other operations that only work on
  anonymous memory fail with `EINVAL`.
* `/proc/PID/maps` and `/proc/PID/map_files` show the VMA as
  `/memfd:NAME (deleted)`. A brk heap is no longer labelled `[heap]`.
* A later checkpoint dumps these VMAs as private file mappings of a memfd,
  not as anonymous memory.
* memfd pages are charged to the memory cgroup that populated them, usually
  the provider's. Only the copy-on-write pages are charged to the restored
  task's cgroup.
* Writes to the memfd after restore are visible to the task in pages it has
  not written yet, and truncating the memfd causes `SIGBUS`. After
  `WAIT_READY` the provider must neither modify nor shrink the file. It should
  seal it (`F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE`) or drop all writable
  references.

A provider should return `-ENOTSUP` for any VMA where these semantics are not
acceptable. CRIU then restores that VMA as ordinary anonymous memory.

## Dump

The provider may also receive the images written by `criu dump`:

1. CRIU sends `INIT` before it opens any image, and before the `pre-dump`
   action scripts run.
2. For each image, CRIU sends `OPEN_IMAGE` with the image name and its open
   flags (`O_WRONLY | O_CREAT | O_TRUNC`). The returned FD must be writable.
   CRIU writes the standard image format to it sequentially. If the provider
   returns `-ENOTSUP`, CRIU writes that image to the local images directory.
   Once CRIU has started writing an image to a provider FD, any error is fatal
   and the image is not rewritten locally.
3. After all image data has been flushed, CRIU sends `COMMIT`, before it runs
   the `post-dump` action scripts. The provider must not reply until it has
   durably stored the images and prepared anything it needs for a later
   restore. A `post-dump` script, e.g. one that starts a migration, can
   therefore rely on the checkpoint being complete. If `COMMIT` fails, the
   dump fails: the `post-dump` scripts are not run and the tasks are resumed,
   as for any other dump error. A failure before `COMMIT` results in `ABORT`.
   A non-zero exit code from a `post-dump` script does not revoke a committed
   checkpoint. It only makes CRIU resume the tasks.
   The dump can still fail after `COMMIT`, e.g. in a plugin's `DUMP_FINISH`
   hook or while CRIU cleans up the dumped tasks. CRIU then reports an error,
   but the provider already holds a complete checkpoint and gets no further
   message.

`inventory.img` is always written locally, because restore reads it before it
sends `INIT`. `criu pre-dump` never uses the provider, and the dump side never
sends `GET_VMA`, `GET_SHARED` or `WAIT_READY`. The provider can serve the
memory objects on restore by parsing the `mm-*.img`, `pagemap-*.img`,
`pages-*.img` and related images it received.

## Provider checklist

* Answer every request with exactly one response, and attach an FD only to a
  successful `OPEN_IMAGE`, `GET_VMA` or `GET_SHARED` reply.
* Return a new open file description for each request.
* Image FDs: readable and seekable on restore, writable on dump.
* VMA FDs: full VMA content at `[offset, offset + length)`, with the
  matching huge-page size for hugetlb.
* memfd FDs: real memfd, correct size, `MFD_ALLOW_SEALING`, no seals, the
  original name and hugetlb flags.
* Reply to `WAIT_READY` only when all returned objects are populated, and do
  not modify them afterwards.
* Return `-ENOTSUP` for anything you do not want to serve.

## Limitations

* Only private anonymous VMAs, shared anonymous memory and memfds can be
  provider-backed. Private file mappings, SysV IPC shared memory and special
  mappings always use the normal path.
* Parent (pre-dump) images are always read locally.
* CRIU refuses to start a provider session together with `--stream`,
  `--lazy-pages`, a page server (`--page-server`), or `--auto-dedup` on
  restore, which punches holes into the page images.
* CRIU does not validate the size or type of the FDs it maps. A wrong FD can
  make the restored application crash later with `SIGBUS`.

## Implementation

* [`criu/extmem.c`](../../criu/extmem.c): session state and the protocol client.
* `criu/image.c`: `do_open_image()` asks the provider before it opens an image
  locally.
* `criu/mem.c`: `premap_provider_vma()` and `plan_priv_vmas()` handle private
  VMAs. The restorer blob moves provider mappings like any other premapped VMA.
* `criu/shmem.c` and `criu/memfd.c`: `open_shmem()` and
  `memfd_open_inode_nocache()` handle shared objects.
* `criu/cr-restore.c` and `criu/cr-dump.c`: session start, `WAIT_READY`,
  `COMMIT` and `ABORT`.
* `test/zdtm/extmem_provider.py`: a mock provider used by the
  `zdtm/static/extmem_*` tests.
