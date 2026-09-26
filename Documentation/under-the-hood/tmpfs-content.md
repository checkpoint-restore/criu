# tmpfs Content

Most filesystems that CRIU meets are backed by something that outlives the
checkpoint, so only the mount itself has to be restored. A tmpfs mount has no
backing store: if its content is not saved, it is gone. CRIU therefore dumps
the files inside a tmpfs mount as part of the image set.

This page describes how that works today.

## Image files

Two image descriptors carry tmpfs content
(`criu/image-desc.c`):

| descriptor | file name | key | status |
| --- | --- | --- | --- |
| `CR_FD_TMPFS_DEV` | `tmpfs-dev-%u.tar.gz` | superblock device (`s_dev`) | in use |
| `CR_FD_TMPFS_IMG` | `tmpfs-%u.tar.gz` | mount id (`mnt_id`) | deprecated |

Both are opened with `O_NOBUF`, since the payload is written by an external
process rather than through the usual image writing helpers.

Unlike other CRIU images, these are not protobuf. Each one is a gzip
compressed tar archive of the mount, and CRIU does not look inside it.

### Why `CR_FD_TMPFS_IMG` is deprecated

The content of a tmpfs belongs to its superblock, not to any one mount of
it. The same superblock can be mounted in several places, and each of those
mounts has its own mount id, so `mnt_id` does not identify the filesystem
whose content is being saved. Keying the archive on it meant that one
filesystem mounted twice looked like two different things to dump and
restore.

Commit 697211908 ("tmpfs: use device number instead of mnt_id in image
names") switched to the superblock device number, which is unique per
filesystem, so there is now exactly one archive per tmpfs no matter how many
times it is mounted.

Nothing writes `CR_FD_TMPFS_IMG` any more. `tmpfs_dump()` only ever opens
`CR_FD_TMPFS_DEV`, and the only remaining use of the old descriptor is the
fallback in `tmpfs_restore()`, which tries `CR_FD_TMPFS_DEV` first and falls
back to `CR_FD_TMPFS_IMG` when that image is empty. That exists so that image
sets written before the change can still be restored.

## How the content is saved

The whole mechanism lives in `criu/filesystems.c`, in `tmpfs_dump()` and
`tmpfs_restore()`. Both shell out to `tar`.

Dump opens the mountpoint, moves the resulting descriptor to stdin so that
`tar` can refer to it as `/proc/self/fd/0`, and runs:

```
tar --create --gzip --no-unquote --no-wildcards --one-file-system \
    --check-links --preserve-permissions --sparse --numeric-owner \
    --directory /proc/self/fd/0 .
```

Restore is the mirror image:

```
tar --extract --gzip --no-unquote --no-wildcards --directory <mountpoint>
```

The flags are there for the following reasons:

* `--one-file-system` keeps the archive to the tmpfs mount itself, so nested
  mounts are handled separately rather than being copied into this archive.
* `--check-links` makes `tar` warn if it stores a file with a link count above
  one but does not archive every one of its names.
* `--sparse` stores files with holes efficiently.
* `--preserve-permissions` and `--numeric-owner` keep modes and ownership as
  raw numbers, without trying to resolve user and group names, which would be
  meaningless in another namespace.
* `--no-unquote` and `--no-wildcards` stop `tar` from interpreting file names
  that contain backslashes or glob characters.

`devtmpfs_dump()` and `devtmpfs_restore()` reuse the same helpers when
devtmpfs is virtualized, which `kerndat_fs_virtualized()` decides.

## User namespaces

Dump runs `tar` through `cr_system_userns()` rather than `cr_system()`. When
the dumped task tree has its own user namespace, CRIU passes the pid of the
root task, and `cr_system_userns()` enters that user namespace before exec.
Without this, files owned by UIDs that are not mapped on the host would not be
readable.

Restore uses plain `cr_system()`, as the mount tree is already being rebuilt
inside the target namespaces at that point.

## Implications of using tar

Some consequences worth being aware of:

* **An external `tar` is required at run time.** CRIU does not implement the
  archive format itself, and the flag set above is GNU `tar` specific. This is
  why `contrib/dependencies/apk-packages.sh` and
  `contrib/dependencies/pacman-packages.sh` install `tar` explicitly.
* **tmpfs content does not go through the CRIU image pipeline.** Because the
  payload is an opaque archive produced by another process, it is not affected
  by the image compression added for memory pages, and it is not inspectable
  with `crit`. The archive carries its own gzip compression instead.
* **Extended attributes are not requested.** `--xattrs` is not among the flags
  passed to `tar`, and `tar` does not store extended attributes by default.
* **Errors are reported coarsely.** `cr_system_userns()` logs the exit status
  of the child without naming the command, and the callers add only
  `Can't dump tmpfs content` or `Can't restore tmpfs content`.

## Test coverage

The tmpfs tests live in `test/zdtm/static`:

| test | what it covers |
| --- | --- |
| `tempfs` | content of a regular file, plus an overmounted tmpfs |
| `tempfs_ro`, `tempfs_ro02` | read-only tmpfs mounts |
| `tempfs_subns` | tmpfs in a nested mount namespace |
| `tempfs_overmounted`, `tempfs_overmounted01` | overmounted tmpfs trees |

Ownership is exercised only indirectly, through the `uns` flavor of these
tests. Hard links, sparse files, symlinks, file modes and extended attributes
are not covered.
