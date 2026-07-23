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
pre-dump, or restore). It returns `0` after successful initialization and a
nonzero value to abort plugin loading. An optional plugin can instead initialize
successfully in a disabled state when its external service or library is not
available. The finalization callback receives the operation result, allowing a
plugin to clean up resources or undo temporary state after a failed checkpoint
or restore.

Plugins register their callbacks through `criu-plugin.h`. A plugin may implement any
subset of the supported callback interfaces. When a callback does not handle a
particular object, it should return `-ENOTSUP`, allowing CRIU to continue trying
other registered plugins.

## Plugin options

CRIU accepts plugin-owned settings through
`--plugin-option=PLUGIN.NAME[=VALUE]`, the RPC API, and libcriu. The plugin name
acts as a namespace, preventing independently developed plugins from choosing
the same long-option name. The RPC `plugin_options` field contains the same raw
`PLUGIN.NAME[=VALUE]` strings. Libcriu clients append them with
`criu_add_plugin_option()`.

In command-line and configuration-file syntax, the first `.` separates the
plugin namespace from the option name, and the first `=` separates the name
from its value. Plugin and option names must be nonempty; an empty value is
allowed for the plugin to interpret. Options may omit `=VALUE` to represent
flags. A plugin must reject missing values for its own options that require
arguments before calling `getopt_long()`, which could otherwise consume the
following option as a value. CRIU validates only the outer syntax; the plugin
decides which names it supports and whether each value is valid. CRIU retains repeated options in
input order instead of interpreting or combining them. Normal configuration
options come first, followed by options from a request-specific configuration
file and then RPC request options. Service worker initialization resets plugin
options, including startup defaults; request-specific options are cleared before
the next request. A plugin can implement the usual last-setting-wins behavior
by processing the complete array in order.

Plugins retrieve CRIU's argument array with
`criu_plugin_get_options()`. CRIU prepends `--` to each supplied option, adds a
synthetic `argv[0]`, and terminates the array with `NULL`, allowing the plugin to
use a standard parser such as `getopt_long()`:

```c
static const struct option options[] = {
	{ "example.option", required_argument, NULL, 'o' },
	{},
};
char **argv;
int argc;
int option;
int i;
int ret;

ret = criu_plugin_get_options(&argc, &argv);
if (ret)
	return ret;

for (i = 1; i < argc; i++) {
	if (!strcmp(argv[i], "--example.option"))
		return -EINVAL;
}

opterr = 0;
optind = 0;
while ((option = getopt_long(argc, argv, ":", options, NULL)) != -1) {
	switch (option) {
	case 'o':
		/* Check the consumed name exactly, then parse or copy optarg. */
		break;
	case '?':
		/* This option may belong to another plugin. */
		break;
	case ':':
	default:
		ret = -EINVAL;
		goto out;
	}
}
out:
	return ret;
```

Every plugin receives all plugin options and must skip unknown ones. This also
means that CRIU does not report a misspelled option or an option for a plugin
that is not installed. A plugin should still reject malformed values for the
options it recognizes. CRIU owns the returned array and its strings; plugins
must not free them or modify the strings. A plugin that retains values across
requests must copy them, because request cleanup releases request arguments.

`getopt_long()` accepts unique abbreviations of long option names. A plugin
that intends to ignore misspelled arguments must compare the consumed token in
`argv[optind - 1]` through its `=` with the complete registered name before
using `optarg`. The parser also keeps process-global and libc-private state.
Every plugin must start a new scan with `optind = 0`; saving and restoring the
visible globals does not make an interrupted scan resumable.

Plugins can print their options in `criu --help` by registering a
`CR_PLUGIN_HOOK__PRINT_HELP` callback with signature `int (void)`. Every help
hook runs; return zero on success or a negative error on failure. Write help
to standard output. CRIU loads plugins from the usual `-L`/`--libdir`,
`CRIU_LIBS_DIR`, or default directory, without calling plugin initialization
or finalization callbacks. Help hooks must not depend on initialized device
state. Shared-object constructors and destructors still run.

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

A plugin needs to implement only the callbacks it uses. Return `-ENOTSUP` to
decline a hook and let CRIU try the next plugin. Normal dispatch stops at the
first other result, whether it indicates success or an error. The global
`DUMP_DEVICES_LATE`, `RESTORE_INIT`, and `PRINT_HELP` hooks are broadcast
instead: CRIU invokes every registered handler, ignores `-ENOTSUP`, and reports
the first other nonzero result after all handlers have run.

Success values depend on the hook. Most dump and lifecycle hooks return `0`.
`RESTORE_EXT_FILE` and `RESTORE_UNIX_SK` return a valid, nonnegative descriptor
for the restored file or socket. `UPDATE_VMA_MAP` returns `1` to apply
`new_pgoff`, or `0` to leave the page offset unchanged. Other negative values
represent errors.

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
unlocking the application during restore. One `cuda_plugin.so` contains both a
direct CUDA Driver API backend and a backend that invokes the
`cuda-checkpoint` utility. It selects the direct backend when the installed
driver supports it and otherwise uses the utility. The backend is selected
once during initialization and is never changed after a device operation has
started.

The AMD GPU plugin follows the same lifecycle through KFD ioctls and
device-file/VMA hooks, but stores and restores different driver-managed
objects.

This design avoids putting GPU API interception in the application's critical
path. The application continues to use its normal CUDA or ROCm interfaces;
the plugin participates only at checkpoint and restore boundaries.

## Plugin identity and inventory requirements

Every descriptor contains a plugin API `version`, which determines whether the
library is compatible with the loader and callback ABI, and a stable logical
`name`. CRIU does not derive either value from the shared-object filename.
Plugin-specific image formats need their own compatibility versioning.

Install exactly one implementation of a logical plugin. The generic loader
does not choose between alternative implementations or infer precedence from
their filenames. If one plugin needs to support several runtime interfaces,
it should contain that dispatch itself and register a single descriptor.

When a dump actually depends on a plugin, the plugin adds its logical name to
the image inventory. On restore, it removes that exact name only after it has
confirmed that it can satisfy the requirement. Any required names left in the
inventory after plugin initialization cause restore to fail. Thus an optional
plugin whose backend is unavailable can remain disabled without silently
restoring an image that requires it.

Plugin authors register a descriptor with the public macro:

```c
CR_PLUGIN_REGISTER("example", init, fini)
```

## Examples

The CRIU source tree contains plugin-oriented tests under `test/` and example
plugin code can be found in the `plugins/` directory. These examples show how
to register callbacks, create plugin images, and coordinate external resources
with CRIU's dump and restore stages.
