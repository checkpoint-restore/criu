# Saving and restoring tmpfs content

When checkpointing mount namespaces, CRIU saves the content of tmpfs
filesystems that it will recreate during restore. tmpfs stores files in
virtual memory, and their content is lost when the filesystem is no longer
in use. This can happen when a container stops and its mount namespace is
destroyed, unless another mount or an open file keeps the filesystem alive.
CRIU saves a copy of these files so they can be restored after the original
tmpfs filesystem is gone.

This happens only when CRIU dumps mount namespaces. `dump_mnt_namespaces()`
requires `CLONE_NEWNS` in `root_ns_mask` and skips CRIU's own mount namespace.
It processes the root task's mount namespace and any additional mount
namespaces collected from the process tree. Filesystems supplied through
the namespace root or external mounts, and mounts handled by plugins, are
excluded from the filesystem dump callbacks.

For a container or Kubernetes Pod, the runtime's mount configuration
therefore determines which tmpfs filesystems CRIU archives. A tmpfs volume
supplied as an external mount must be made available separately at restore.
CRIU does not include its content in the tmpfs archive.

CRIU saves tmpfs content as a gzip-compressed tar archive.
`tmpfs_dump()` and `tmpfs_restore()` in `criu/filesystems.c` run an external
`tar` process to create and extract it.

The archive uses the filename `tmpfs-dev-%u.tar.gz.img`, with the superblock device
number (`s_dev`) so mounts sharing a filesystem share one archive.
These images contain raw archives rather than protobuf messages.

Older versions of CRIU used `tmpfs-%u.tar.gz.img` for these archives, with
the mount ID instead of the device number. This naming scheme is deprecated,
but restore still accepts it for backward compatibility with older checkpoints.

## Dump

`tmpfs_dump()` opens the mountpoint and passes its file descriptor as stdin
to `tar`. The archive is written directly to the image file through stdout:

```
tar --create --gzip --no-unquote --no-wildcards --one-file-system \
    --check-links --sparse --numeric-owner --acls --xattrs \
    --xattrs-include='user.*' --xattrs-include=security.capability \
    --directory /proc/self/fd/0 .
```

When dumping a tree with its own user namespace, `cr_system_userns()` enters
the root task's user namespace before executing `tar`. This saves UIDs and
GIDs as seen inside that namespace rather than host IDs. `--numeric-owner`
keeps user and group names out of the archive.

## Restore

`tmpfs_restore()` passes the archive as stdin to `tar` and extracts it at the
mount's service mountpoint:

```
tar --extract --gzip --no-unquote --no-wildcards \
    --preserve-permissions --acls --xattrs \
    --xattrs-include='user.*' --xattrs-include=security.capability \
    --directory <mountpoint>
```

Restore runs in the target user namespace and uses the numeric IDs saved in
the archive. `--preserve-permissions` restores the saved file permissions
without applying the extracting process's umask.

Both commands use `--acls` to preserve POSIX ACLs. The xattr options preserve
attributes in the `user.*` namespace and `security.capability`, which stores
file capabilities. Other extended attributes are excluded.
