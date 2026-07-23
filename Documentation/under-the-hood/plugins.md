# CRIU plugins

Linux processes often depend on external resources that cannot be handled
generically. A CRIU plugin lets the resource owner save and restore that
state while CRIU manages the process checkpoint and restore lifecycle.

## A plugin is just a shared library

Under the hood, a plugin is simply a shared library that CRIU loads before
checkpointing or restoring a process. These libraries are typically installed
under `/usr/lib/criu/` and discovered by CRIU's plugin loader.

Each library can provide initialization and finalization callbacks for every
CRIU stage. The initialization callback receives the current operation (dump,
pre-dump, or restore) and may fail if that operation is not supported. The
finalization callback receives the operation result, allowing the plugin to
clean up resources or undo temporary state after a failed checkpoint or
restore.

Plugins register their callbacks through `criu-plugin.h`. A plugin may implement any
subset of the supported callback interfaces. When a callback does not handle a
particular object, it should return `-ENOTSUP`, allowing CRIU to continue trying
other registered plugins.

## Plugin headers

Public plugin headers use the `criu-` prefix. Plugin authors should build
against the `include/criu-plugin.h` header that matches the version of the
CRIU loader they are targeting. The header defines the descriptor,
registration macros, callback types, and helper functions available to plugins.

## Plugin image files

CRIU stores checkpoint data in image files encoded with Protocol Buffers.
Where practical, plugins should use the same format for plugin-specific
images.

Plugin image files are created in CRIU's image directory. Use
`criu_get_image_dir()` to obtain a file descriptor for that directory
rather than relying on its path, since the path may not be reachable
after a process is restored in a new mount namespace.

## Plugin callback interfaces

CRIU invokes registered callbacks when it encounters a checkpoint object
that it cannot handle itself. For example, if CRIU encounters a file that
has been marked as external, it invokes the registered external-file
callbacks. Each plugin checks whether it is responsible for handling that
file. If so, it saves any additional state it requires; otherwise, it
returns `-ENOTSUP` so that CRIU can try the next plugin.

Each callback receives an identifier for the serialized object, which the
plugin can use to locate the corresponding object during restore.

The callback families include:

* external Unix sockets;
* external files;
* external bind mounts;
* external network links;
* device-backed VMAs and device checkpoint/restore stages; and
* selected socket address and restore lifecycle operations.

A plugin needs to implement only the callbacks it uses. A callback should
return `0` after successfully handling an object, `-ENOTSUP` if it does not
apply, and any other negative value to report an error. CRIU stops invoking
callbacks after the first error.

Hooks are also used to coordinate external device state with CRIU's process
lifecycle. For example, a GPU plugin can pause device work before CRIU freezes
the CPU processes, save the device state after the processes are frozen, and
restore or resume the device late in restore. This ordering is essential for
creating a consistent CPU-and-device checkpoint.

### External Unix sockets

An external Unix socket is checkpointed without its peer. The plugin preserves
the state that belongs to the peer, then reconnects or restores the socket:

```c
int cr_plugin_dump_unix_sk(int fd, int id);
int cr_plugin_restore_unix_sk(int id);
```

This is useful for sockets whose peer owns subscription or protocol state,
such as a D-Bus connection.

### External files

Plugins can checkpoint and restore files that CRIU cannot handle generically:

```c
int cr_plugin_dump_ext_file(int fd, int id);
int cr_plugin_restore_ext_file(int id, bool *retry_needed);
```

### External bind mounts

External mounts have a source outside the namespace being checkpointed. The
dump callback receives the mount point and an identifier. During restore, the
plugin receives the target path, the old namespace root, and an indication of
whether the mount point is a file or directory:

```c
int cr_plugin_dump_ext_mount(char *mountpoint, int id);
int cr_plugin_restore_ext_mount(int id, char *mountpoint,
                                char *old_root, int *is_file);
```

The `old_root` path lets a plugin locate files from the original namespace.
The restore path may differ from the original mount path because CRIU can move
the mount into its final location later.

### External network links

When a network namespace contains a physical device, macvlan, or vlan that is
managed outside the namespace, CRIU can ask a plugin to handle it:

```c
int cr_plugin_dump_ext_link(int index, int type, char *kind);
```

Here `index` is the link index, `type` is an `ARPHRD_*` value, and `kind` is
the link driver name. Restoring the external link is normally coordinated by
the `setup-namespaces` action script.

## GPU plugins

GPU state is external to the CPU process state managed by CRIU. A GPU plugin
bridges that boundary: CRIU freezes and restores the process tree, while the
plugin uses the GPU driver or a driver-provided utility to pause, checkpoint,
restore, and resume the device state.

The CUDA plugin uses device hooks to coordinate these operations. It pauses
CUDA activity before the target CPU processes are frozen, checkpoints GPU
state after the CPU and GPU work is quiesced, and restores the GPU state before
unlocking the application during restore. The AMD GPU plugin follows the same
lifecycle through KFD ioctls and device-file/VMA hooks, but stores and restores
different driver-managed objects.

This design avoids putting GPU API interception in the application's critical
path. The application continues to use its normal CUDA or ROCm interfaces;
the plugin participates only at checkpoint and restore boundaries.

## Plugin identity and implementation versions

Every plugin descriptor has two independent version values:

* `version` is the CRIU plugin API version. It determines whether the plugin
  is compatible with the loader and callback ABI.
* `implementation_version` identifies an implementation of a logical plugin.
  It allows multiple implementations of the same plugin to be discovered and
  distinguished before CRIU selects one.

The descriptor `name` is the stable logical plugin identity. It must not be
derived from the shared-object filename. For example, two CUDA implementations
can both use the logical name `cuda` while declaring implementation versions 1
and 2.

Implementation versions identify alternative implementations of one logical
plugin, not separate hooks that should run together. CRIU discovers all
candidates before initialization, selects the highest implementation version,
and initializes only that implementation. This prevents two implementations
from both manipulating the same external resource.

Plugin authors should use the registration macros from `criu-plugin.h`:

```c
CR_PLUGIN_REGISTER("cuda", init, fini)
```

The existing macro declares implementation version 1. To declare another
implementation, use the versioned form:

```c
CR_PLUGIN_REGISTER_VERSIONED("cuda", 2, init, fini)
```

Plugins that do not declare an implementation version default to version 1.
CRIU discovers all plugin candidates before calling their initialization
callbacks or registering their hooks. If several implementations have the
same logical name, CRIU selects the numerically highest implementation
version and unloads the older versions.

CRIU reports an error and fails plugin initialization when two plugins have
the same logical name and implementation version (duplicates).

## Examples

The CRIU source tree contains plugin-oriented tests under `test/` and example
plugin code can be found in the `plugins/` directory. These examples show how
to register callbacks, create plugin images, and coordinate external resources
with CRIU's dump and restore stages.
