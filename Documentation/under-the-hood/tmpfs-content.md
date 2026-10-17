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
| `CR_FD_TMPFS_DEV` | `tmpfs-dev-%u.tar.gz.img` | superblock device (`s_dev`) | in use |
| `CR_FD_TMPFS_IMG` | `tmpfs-%u.tar.gz.img` | mount id (`mnt_id`) | deprecated |

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

The superblock device number is unique per filesystem, so keying the archive
on it gives exactly one archive per tmpfs however many times that tmpfs is
mounted. This is what `CR_FD_TMPFS_DEV` does.

Nothing writes `CR_FD_TMPFS_IMG` any more. `tmpfs_dump()` only opens
`CR_FD_TMPFS_DEV`. The single remaining use is in `tmpfs_restore()`, which
tries `CR_FD_TMPFS_DEV` first and falls back to `CR_FD_TMPFS_IMG` when that
image is empty, so that image sets written by older versions still restore.

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

* `--one-file-system` stops `tar` from descending into a directory that lives
  on a different filesystem, so another tmpfs mounted inside this one leaves
  an empty directory in the archive and is dumped as its own. The test is the
  device number rather than the mount, so a bind mount of this same tmpfs is
  still archived, and its files appear under both paths.
* `--check-links` makes `tar` warn if it stores a file with a link count above
  one but does not archive every one of its names.
* `--sparse` stores files with holes efficiently.
* `--preserve-permissions` is an extraction option, so passing it on the
  create side has no effect: the modes are recorded in the archive either way.
  It is not passed on extract, where it would matter, but `tar` already
  applies the recorded modes when it runs as root, which is the case here.
* `--numeric-owner` stores and restores ownership as raw uid and gid values,
  without resolving user and group names, which would be meaningless in
  another namespace.
* `--no-unquote` and `--no-wildcards` stop `tar` from interpreting file names
  that contain backslashes or glob characters.

`devtmpfs_dump()` and `devtmpfs_restore()` reuse the same helpers when
devtmpfs is virtualized, which `kerndat_fs_virtualized()` decides.

## User namespaces

`cr_system()` is the helper CRIU uses to run an external program. It forks,
points the child's stdin, stdout and stderr at descriptors the caller passes
(stdout and stderr default to the CRIU log), execs the program and waits for
it. The tmpfs helpers use it to drive `tar`, handing it the image file as the
end that `tar` writes to or reads from.

`cr_system_userns()` is the same helper with one addition: given a pid, the
child joins that task's user namespace and resets its uid and gid before exec.
`cr_system()` is simply a call to it with no pid.

Dump needs that addition. When the dumped task tree has its own user
namespace, CRIU passes the pid of its root task so that `tar` runs under that
namespace's id mapping. Without it, files owned by uids that are not mapped on
the host would not be readable.

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
* **Errors are reported per archive, not per file.** `cr_system_userns()`
  logs the failing command and its exit status, for example
  `tar exited, status=2`, and the callers add only `Can't dump tmpfs content`
  or `Can't restore tmpfs content`. Which file inside the mount caused the
  failure is only visible in the messages `tar` itself writes to the CRIU
  log.

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
