# LiveUpdate (LUO): Preserving File Descriptors Across Kexec Reboot

**LiveUpdate Orchestrator (LUO)** is a Linux kernel subsystem that supports serializing a process's file descriptor data in memory; after a `kexec` reboot, the new kernel takes over the in-memory contents. `memfd_luo` is a kernel facility built on top of LUO that handles serialization/deserialization of memfd file data. With LUO and **memfd**, CRIU can keep checkpoint images resident in memory without writing them to disk, re-mount the images on the new kernel, and complete the restore. This document describes how CRIU implements this capability.

## Three Core Dependent Components

| Component               | Role                                                                                                                                                                                         |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `memfd_create(2)`       | RAM-backed anonymous file; the container for each image                                                                                                                                      |
| `/dev/liveupdate` (LUO) | The userspace-facing interface exposed by the kernel LUO; it manages sessions and attaches a token to every memfd to be preserved, which restore uses to retrieve the memfd back after kexec |
| Kexec Handover (KHO)    | The underlying transport mechanism for LUO across kexec; LUO does not move bytes directly, relying on KHO to hand over metadata and preserved physical pages                                 |

## CRIU's Architecture

The integration code is split into two layers, with clear responsibilities on the CRIU side and the kernel side:

```
┌─────────────────────────────────────────────────────────────┐
│                   CRIU side (user space)                    │
│                                                             │
│   --memfd-images                                            │
│        │                                                    │
│   ┌────▼────────────────────────────────────────────────┐   │
│   │  cr-dump.c / cr-restore.c   flow orchestration      │   │
│   ├─────────────────────────────────────────────────────┤   │
│   │  luo.c   session creation, memfd attachment, token  │   │
│   │          generation, metadata (de)serialization,    │   │
│   │          daemonization                              │   │
│   ├─────────────────────────────────────────────────────┤   │
│   │  image.c / bfd.c   memfd-backed open / close_image  │   │
│   ├─────────────────────────────────────────────────────┤   │
│   │  images/luo.proto   on-disk session metadata format │   │
│   └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│   /dev/liveupdate  ◄─────┼────  ioctl: CREATE_SESSION, etc. │
└──────────────────────────┼──────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────┐
│                   Kernel side (kernel space)                │
│                                                             │
│   memfd file handler    ◄── memfd contents preserved        │
│                          across kexec                       │
│   serialization         ──  writes session metadata into    │
│                          KHO so the new kernel can          │
│                          rebuild the session                │
│   deserialization       ──  rebuilds the session on the     │
│                          new kernel                         │
│   KHO                   ◄─  metadata + memory pages         │
│                          handed over across kexec           │
└─────────────────────────────────────────────────────────────┘
```

### On-disk image format: `luo-metadata`

A new image type `CR_FD_LUO_METADATA` carries the session metadata required by restore, defined in `images/luo.proto`. Its core structure has only two fields:

- `session_name`: the session name, used by the restore side to attach to the correct LUO session.
- `fd_mappings`: a list of path → token mappings, telling CRIU how to translate an image file path back to a memfd token and ultimately locate the image.

The image is written with the `O_FORCE_LOCAL` flag, so the metadata always lives on disk — it is the bootstrap that the restore-side CRIU reads first. The image payloads themselves may live in memfds.

### CLI option: `--memfd-images`

`check_options()` enforces three invariants on the option:

1. It is only meaningful for `dump` and `restore` modes.
2. The kernel must advertise `memfd_create` support via `kdat.has_memfd`.
3. It is mutually exclusive with `--stream`, because both options fundamentally replace the local-filesystem image backend.

If `--memfd-images` is set but `luo_init_session()` later returns `-ENOTSUP`, CRIU **silently falls back** to the regular disk backend by clearing `opts.images_in_memfd`. This graceful-degradation path keeps the workflow alive on misconfigured hosts.

### `luo.c` API

The following describes the API across the dump and restore stages:

#### Dump stage

| Function                          | When called            | Role on images                                                                                                                                                                                |
| --------------------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `luo_init_session(name)`          | dump start             | Opens a LUO session context for the subsequent images; no specific image is involved yet.                                                                                                     |
| `luo_preserve_fd(fd, &tok, path)` | dump, once per image   | Hands the image fd (memfd) over to the kernel session, which pins its physical pages so the contents survive kexec; also derives a token from `path` and records the `(path, token)` mapping. |
| `luo_save_image_metadata()`       | dump, after all images | Writes the session name and all `(path, token)` mappings into the `CR_FD_LUO_METADATA` image, used by the restore side as the bootstrap lookup.                                               |
| `luo_daemonize_and_wait()`        | dump end               | Forks a background process to hold the session FD, ensuring the LUO session will not be reclaimed by the kernel before kexec.                                                                 |

#### Restore stage

| Function                             | When called             | Role on images                                                                                                                    |
| ------------------------------------ | ----------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `luo_load_image_metadata()`          | restore read phase      | Restores the session name and all `(path, token)` mappings from the `CR_FD_LUO_METADATA` image.                                   |
| `luo_retrieve_session(name)`         | restore start           | Re-opens the same-named session on the new kernel and installs the session FD so that preserved images can be looked up by token. |
| `luo_retrieve_fd_by_path(path, &fd)` | restore, once per image | Looks up the token for `path` in the mapping table and asks the kernel for the corresponding image fd (memfd).                    |
| `luo_retrieve_fd(token, &fd)`        | restore, low-level      | Asks the kernel for an image fd by raw token (called internally by `luo_retrieve_fd_by_path`).                                    |
| `luo_finish_session()`               | restore end             | Explicitly tells the kernel to release the session.                                                                               |
| `luo_cleanup(finish)`                | dump & restore end      | Releases the in-memory mapping list and closes the session FD.                                                                    |

#### Why a separate daemon process holds the session FD

On the kernel side, a LUO session stays alive **only as long as some process holds the session FD**. CRIU's main process exits after `dump` finishes, so before returning, `luo_daemonize_and_wait()` forks a child process to hold the session FD.

#### Token generation

Tokens are **CRIU-side** identifiers, used on the restore side to locate the corresponding memfd by token. CRIU folds two inputs into a 64-bit value, guaranteeing that **within a single dump session** every preserved FD gets a unique, non-colliding token:

- a string hash of the image path,
- a monotonically increasing global counter.

### Image I/O: writing and reading memfd images

When `--memfd-images` is set, `do_open_image()` calls `try_dump_memfd()` on the dump side and `try_restore_luo()` on the restore side, both of which bypass `openat()` and take the memfd path. The `O_FORCE_LOCAL` flag is the exception: the LUO metadata image carries this flag and always goes to disk.

Three helpers split the responsibilities:

- `bfd_prepare_image()`: wraps the bfd layer around an already-open FD and writes / checks the magic header (called in `do_open_image`).
- `mark_for_luo_preserve()`: sets the pending flag and stores the path for the current image; the actual `PRESERVE_FD` ioctl is deferred to `close_image()`.
- `bfd_flush()`: flushes the bfd layer's buffered writes to the memfd, ensuring bytes are visible to the kernel before any follow-up operations (called in `close_image`).

#### The flush-then-preserve ordering

When handling a luo image, `close_image()` runs three steps in order:

1. **flush**: `bfd_flush()` drains the bfd layer's buffered writes so the memfd actually holds the image bytes.
2. **preserve**: `luo_preserve_fd()` hands the fd to the current session (with a token derived from `path`). **At this moment the image data is serialized and pinned on its physical pages**.
3. **close**: `bclose()` closes the FD. This is safe because the kernel session still owns the preserved physical pages and metadata.

#### lseek to 0 on restore

After retrieving a memfd during restore, the FD offset is wherever the dump left it (typically end-of-file). CRIU explicitly calls `lseek(fd, 0, SEEK_SET)` before wrapping the FD with `bfdopenr()`, so that the buffered reader starts from the image's first byte.

### Lifecycle at a Glance

**Dump (`criu dump -t PID -D DIR --memfd-images`):**

```
cr_dump_tasks
├── collect_namespaces()               ← prior normal operations
├── luo_init_session("criu-dump-<pid>")  ← [LUO#1] ioctl CREATE_SESSION → service FD
├── for every image:
│     open_image(type, O_DUMP)
│       ├── try_dump_memfd() → memfd_create("memfd_luo:<path>")   ← [LUO#2] use memfd
│       ├── mark_for_luo_preserve()                              ← [LUO#3] mark for luo preserve
│       ├── bfdopenw()
│       └── ... writes ...
│     close_image()
│       ├── bfd_flush()
│       ├── luo_preserve_fd()   ← [LUO#4] ioctl PRESERVE_FD, kernel registers memfd
│       └── bclose()
├── cr_dump_finish()
│     ├── luo_save_image_metadata()   ← [LUO#5] write luo-metadata.img to disk
│     ├── luo_daemonize_and_wait()    ← fork daemon, parent returns
│     └── luo_cleanup(false)          ← [LUO#6] parent cleanup
└── exit (daemon keeps running)
   ──── user runs kexec -e ────
       KHO carries LUO state into the new kernel
   ──── (new kernel) ────
```

**Restore (`criu restore -D DIR --memfd-images`):**

```
cr_restore_tasks
├── luo_load_image_metadata()                          ← [LUO#1] parent reads luo-metadata.img
│     └── luo_retrieve_session(name) → session FD installed
├── restore_root_task()
│     ├── open_core()                              ← [LUO#2] parent pre-read: open_image hits LUO
│     │     open_image → ioctl(RETRIEVE_FD) → memfd        retrieve memfd from session
│     │     → lseek(0) + bfdopenr → pb_read_one parse core
│     ├── fork_with_pid()                          ← [LUO#3] child takes over via clone_service_fd
│     ├── close_service_fd(LUO_SESSION_FD_OFF)            SESSION FD taken over (parent closes)
│     └── wait for child task to finish
├── child task: create_children_and_session()
│     └── restore_one_task() → restore_one_alive_task()
│           ├── for every image: open_image(type, O_RSTR)  ← [LUO#2] child reads on demand: open_image hits LUO
│           │     try_restore_luo → ioctl(RETRIEVE_FD) → memfd   retrieve memfd from session
│           │     → lseek(0) + bfdopenr → pb_read_* decode
│           ├── sigreturn_restore()
│           │     ├── luo_cleanup(true)                ← [LUO#4] cleanup before jumping away
│           │     └── JUMP_TO_RESTORER_BLOB → process "comes back to life"
│           └── (never returns)
└── every child task follows the same restore + sigreturn + luo_cleanup path
```

## Kernel Requirements

CRIU's build system detects support at compile time and emits `CONFIG_HAS_LIVEUPDATE` when the feature test passes. The test includes `<linux/liveupdate.h>` and references the `liveupdate_ioctl_create_session` structure. The runtime prerequisites are:

- **Kernel configuration**:
  - `CONFIG_KEXEC_HANDOVER=y`
  - `CONFIG_LIVEUPDATE=y`
  - `CONFIG_LIVEUPDATE_MEMFD=y`
  - `CONFIG_MEMFD_CREATE=y`
- **Boot parameters**:
  - `liveupdate=on` — enables LUO at runtime
  - `kho=on` — if `CONFIG_KEXEC_HANDOVER_ENABLE_DEFAULT=n`
  - `kho_scratch=ll[KMG],mm[KMG],nn[KMG]` (or `,NN%`) — defines the size of the KHO scratch region.
- **UAPI**: `<linux/liveupdate.h>` must expose the five ioctls that CRIU uses:
  - `LIVEUPDATE_IOCTL_CREATE_SESSION`
  - `LIVEUPDATE_IOCTL_RETRIEVE_SESSION`
  - `LIVEUPDATE_SESSION_PRESERVE_FD`
  - `LIVEUPDATE_SESSION_RETRIEVE_FD`
  - `LIVEUPDATE_SESSION_FINISH`

## See also

- [Checkpoint/Restore Architecture](checkpointrestore.md)
- [Dumping Files](dumping-files.md)
- [Stages of Restoration](stages-of-restoring.md)
- [Service Descriptors](service-descriptors.md)
- [Kerndat](kerndat.md)
- [Live Update uAPI (Linux Kernel Documentation)](https://www.kernel.org/doc/html/latest/userspace-api/liveupdate.html)
