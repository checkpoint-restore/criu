# PID Restoration

A critical requirement for successful checkpoint/restore is ensuring that each process and thread is restored with its original **Process ID (PID)** and **Thread ID (TID)**. Applications frequently rely on these IDs for inter-process communication, signal delivery, and as keys for shared resources (such as System V IPC).

## Restoration Mechanisms

CRIU employs two primary methods to request specific PIDs from the Linux kernel during restoration.

### 1. The Legacy Interface: `ns_last_pid`
On older kernels, Linux does not provide a direct way to request a specific PID during a `fork()` or `clone()` call. Instead, CRIU uses the `/proc/sys/kernel/ns_last_pid` interface:
1.  CRIU acquires a global lock (`lock_last_pid`) to minimize the chance of other processes interfering.
2.  It writes `N-1` to `/proc/sys/kernel/ns_last_pid`.
3.  It calls `fork()`.
4.  The kernel assigns the next available PID, which should be `N`.

**Limitations**:
*   **Race Conditions**: Other processes on the system (outside of CRIU's control) might fork and "steal" the intended PID between the write and the fork.
*   **Performance**: Repeatedly writing to the `/proc` filesystem and calling `fork()` is slow, especially for large process trees.
*   **Nesting Complexity**: Handling nested PID namespaces with this interface requires recursively entering namespaces and managing the legacy interface at each level.

### 2. The Modern Interface: `clone3()` with `set_tid`
Introduced in Linux kernel v5.5, the `clone3()` system call provides a much more robust and efficient mechanism via the `set_tid` array in the `clone_args` structure.
*   **Atomic Assignment**: CRIU explicitly specifies the desired PID directly during the creation call.
*   **No Races**: The PID assignment is atomic with process creation, eliminating the risk of PID theft.
*   **Efficiency**: Offers significant performance improvements, particularly during the restoration of large, multi-threaded applications.
*   **Full Hierarchy Support**: CRIU can pass an array of PIDs to `set_tid`, allowing it to simultaneously set the process's identity in all nested PID namespaces.

## Implementation in CRIU

CRIU includes architecture-specific assembly wrappers (`RUN_CLONE3_RESTORE_FN`) to safely execute these calls during the critical restoration phase. 

*   **Automatic Selection**: CRIU automatically detects the presence of `clone3()` and `set_tid` support during the [Kerndat](kerndat.md) phase. If the modern interface is available, it is prioritized.
*   **Thread Restoration**: Individual threads are restored using the same mechanisms, ensuring that their TIDs match the original state.

## External PID namespaces and action scripts

When restoring into an external PID namespace, CRIU selects that namespace
for subsequent forks and creates the restored root task there. It then
resets the namespace for subsequent forks to the coordinating CRIU
process's own PID namespace. The restored task stays in the external
namespace, while CRIU can create helpers and plugin threads in its own
namespace.

The `setup-namespaces`, `post-setup-namespaces`, `post-restore`,
`network-unlock`, `pre-resume`, and `post-resume` action scripts therefore
start in CRIU's PID namespace. Scripts that need to run a command in the
restored task's PID namespace must enter it explicitly. The
`CRTOOLS_INIT_PID` environment variable gives the PID of the restored root
task in CRIU's PID namespace, so a script can use:

```sh
nsenter --target "$CRTOOLS_INIT_PID" --pid -- command
```

## See also
* [Checkpoint/Restore Architecture](checkpointrestore.md)
* [Kerndat](kerndat.md)
* [Restorer Context](restorer-context.md)
