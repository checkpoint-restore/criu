# GitHub Copilot Instructions for CRIU

CRIU (Checkpoint/Restore In User-space) is a specialized tool for checkpointing
and restoring running processes on Linux.

## Coding Style & Conventions
All C code MUST follow the [Linux Kernel Coding Style](https://www.kernel.org/doc/html/latest/process/coding-style.html).

- **Indentation**: Use hard tabs. Set tab width to 8 characters.
- **Line Length**: Preferred limit is 80 characters. Max 120 if it
  significantly improves readability.
- **Braces**:
  - Functions: Opening brace on a new line.
  - Blocks (`if`, `for`, `while`, `switch`): Opening brace on the same line as
    the statement.
- **Spaces**: Use spaces around operators (`+`, `-`, `*`, `/`, `%`, `<`, `>`,
  `=`, etc.).
- **Naming**: Use descriptive, snake_case names for functions and variables.
- **Comments**: Use C-style comments (`/* ... */`).
  - Multi-line format:
    ```c
    /*
     * This is a multi-line
     * comment.
     */
    ```

## Architecture Overview
- **criu/**: Contains the main logic for checkpoint and restore.
- **compel/**: Sub-project for "parasite" code injection and PIE blob
  generation.
- **images/**: Protobuf descriptions for image files. Use these to understand
  the state being saved.
- **restorer**: PIE code that handles the final stages of process restoration.
  See `criu/include/restorer.h` for `CR_STATE_*` definitions.
- **crit**: Tooling for inspecting CRIU image files.
- **soccr**: Library for TCP socket checkpoint/restore.
- **pie/ directories**: Code in these directories (e.g., `criu/pie/`) should be
  self-contained Position-Independent Executable (PIE) code. It MUST NOT
  depend on any external libraries and can only depend on things implemented by
  Compel.

### CRIU Commands
- **dump**: Saves a process tree and all its related resources into a
  collection of image files.
- **restore**: Restores processes from image files to the same state they were
  in before the dump.
- **check**: Checks whether the kernel supports the features needed by CRIU to
  dump and restore a process tree.
- **pre-dump**: Performs the pre-dump procedure, creating a snapshot of memory
  changes since the previous dump/pre-dump (incremental checkpointing).
- **service**: Launches CRIU in RPC daemon mode, listening for commands over a
  socket.
- **dedup**: Starts pagemap data deduplication, minimizing image size by
  obtaining references from parent images.
- **page-server**: Launches CRIU in page server mode to send memory pages over
  the network during migration.

## Development & Testing
- **ZDTM (Zero-Downtime Migration)**: The primary test suite located in
  `test/zdtm`.
- **Test Scope**: Each test case targets a specific kernel primitive type
  (e.g., file descriptors, sockets, timers).
- **Test Purpose**: Verifies that the targeted kernel primitive is
  Checkpointed/Restored (C/R-ed) correctly.
- **Test Executor**: `test/zdtm.py`.
- **Running a test**: `sudo ./test/zdtm.py run -t zdtm/static/env00`.
- **Test Structure**: Tests typically use `test_daemon()` to signal readiness
  and `test_waitsig()` to wait for the C/R cycle to complete. After being
  restored, the test checks that all its resources are still in a valid state.

## Commit Message Guidelines
Follow these principles when forming commits:

- **Separate each logical change into a separate patch**: Each commit must
  represent a single logical change. Separate bug fixes from performance
  improvements or API updates.
- **The commit subject has to start with the sub-system prefix**: Prefix the
  subject with the affected component (e.g., `criu:`, `compel:`, `images:`,
  `test:`, or specific file names like `criu-ns:`).
- **Imperative Mood**: Use the imperative mood in the subject (e.g., "make
  xyzzy do frotz" instead of "changed xyzzy").
- **Detailed Body**: Explain the problem being solved (the "why") and the
  technical details of the implementation (the "how").
- **Hard Wrap**: The commit message has to be hard wrapped at 72 characters.
- **Signed-off-by**: Every commit MUST be signed off (`git commit -s`). This
  certifies the Developer's Certificate of Origin (DCO).
- **Fixes Tag**:
  - For bugs: `Fixes: <12-char-commit-id> ("summary")`. The `<commit-id>` has
    to be the first 12 characters of the commit SHA-1 ID.
  - For GitHub issues: `Fixes: #<issue-number>`
- **Atomicity**: Ensure CRIU builds and tests pass after *every* commit in a
  series to maintain bisectability.
- **No Fixups**: Squash "fixup!" or "work in progress" commits before final
  submission.
