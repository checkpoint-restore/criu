# CRIU (Checkpoint/Restore In User-space)

CRIU is a tool for saving the state of a running application to a set of files
(checkpointing) and restoring it back to a live state. It is primarily used for
live migration of containers, in-place updates, and fast application startup.

It is implemented as a command-line tool called `criu`. The two primary commands
are `dump` and `restore`.

- `dump`: Saves a process tree and all its related resources (file
  descriptors, IPC, sockets, namespaces, etc.) into a collection of image
  files.
- `restore`: Restores processes from image files to the same state they were
  in before the dump.

## Quick Start

To get a feel for `criu`, you can try checkpointing and restoring a simple
process.

1.  **Run a simple process:**
    Open a terminal and run a command that will run for a while. Find its PID.
    ```bash
    sleep 1000 &
    [1] 12345
    ```

2.  **Dump the process:**
    As root, use `criu dump` with the process ID (`-t`) and a directory for the
    image files (`-D`).
    ```bash
    sudo criu dump -t 12345 -D /tmp/sleep_images -v4 --shell-job
    ```
    The `sleep` process will no longer be running.

3.  **Restore the process:**
    Use `criu restore` to bring the process back to life from the images.
    ```bash
    sudo criu restore -D /tmp/sleep_images -v4 --shell-job
    ```
    The `sleep` process will be running again as if nothing happened.

# For Developers and Contributors

This section contains more technical details about CRIU's internals and
development process.

## Dump Process

On dump, CRIU uses available kernel interfaces to collect information about
processes. For properties that can only be retrieved from within the process
itself, CRIU injects a binary blob (called a "parasite") into the process's
address space and executes it in the context of one of the process's threads.
This injection is handled by a subproject called **Compel**.

## Restore Process

On restore, CRIU reads the image files to reconstruct the processes. The goal is
to restore them to the exact state they were in before the dump. The restore
process is divided into several stages (defined as `CR_STATE_*` in
`./criu/include/restorer.h`).

The main `criu` process acts as a coordinator. It first restores resources with
inter-process dependencies (file descriptors, sockets, shared memory,
namespaces, etc.). It then forks the process tree and sets up namespaces.
Finally, it restores process-specific resources like file descriptors and memory
mappings.

A key step involves a small, self-contained binary called the "restorer". All
restored processes switch to executing this code, which unmaps the CRIU-specific
memory and restores the application's original memory mappings. On the final
step, the restorer calls `sigreturn` on a prepared signal frame to resume the
process with the state it had at the moment of the dump.

## Compel

Compel is a subproject responsible for generating the binary blobs used for the
parasite code (for dumping) and the restorer code (for restoring). It provides a
library for injecting and executing this code within the target process's
address space. It is a separate project because the logic for generating and
injecting Position-Independent Executable (PIE) code is complex and
self-contained.

## Coding Style

The C code in the CRIU project follows the
[Linux Kernel Coding Style](https://www.kernel.org/doc/html/latest/process/coding-style.html).
Here are some of the main points:

-   **Indentation**: Use tabs, which are set to 8 characters.
-   **Line Length**: The preferred line limit is 80 characters, but it can be
    extended to 120 if it improves code readability.
-   **Braces**:
    -   The opening brace for a function goes on a new line.
    -   The opening brace for a block (like `if`, `for`, `while`, `switch`) goes
        on the same line.
-   **Spaces**: Use spaces around operators (`+`, `-`, `*`, `/`, `%`, `<`, `>`,
    `=`, etc.).
-   **Naming**: Use descriptive names for functions and variables.
-   **Comments**: Use C-style comments (`/* ... */`). For multi-line comments,
    the preferred format is:
    ```c
    /*
     * This is a multi-line
     * comment.
     */
    ```

## Code Layout

The code is organized into the following directories:

-   `./compel`: The Compel sub-project.
-   `./criu`: The main `criu` tool source code.
-   `./images`: Protobuf descriptions for the image files.
-   `./test`: All tests.
-   `./test/zdtm`: The Zero-Downtime Migration (ZDTM) test suite.
-   `./test/zdtm.py`: The executor script for ZDTM tests.
-   `./scripts`: Helper scripts.
-   `./scripts/build`: Docker image files used for CI and cross-compilation
    checks.
-   `./crit`: A tool to inspect and manipulate CRIU image files.
-   `./soccr`: A library for TCP socket checkpoint/restore.

## Tests

The main test suite is ZDTM. Here is an example of how to run a single test:

```bash
sudo ./test/zdtm.py run -t zdtm/static/env00
```

Each ZDTM test has three stages: preparation, C/R, and results checks. During
the test, a process calls `test_daemon()` to signal it is ready for C/R, then
calls `test_waitsig()` to wait for the C/R stage to complete. After being
restored, the test checks that all its resources are still in a valid state.
