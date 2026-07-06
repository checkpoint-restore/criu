---
applyTo: "**/{criu/pie,compel/plugins,compel/arch/*/plugins}/**/*.{c,h}"
---
# Copilot Instructions for PIE (Position Independent Executable) Code

The code in this directory is compiled as Position Independent Executable (PIE) and is often injected into target processes as "parasite" code.
This environment is extremely restrictive.

## Critical Constraints

1.  **No External Libraries**:
    *   Do **NOT** use functionality from standard libraries (NO `libc`, `pthread`, `printf`, `malloc`, etc.).
    *   The code must be completely self-contained.

2.  **No Global State**:
    *   Avoid introducing new complex global state in PIE/parasite code.
    *   Simple POD (plain data) globals that follow existing patterns in `criu/pie` are acceptable when necessary.
    *   Do not rely on runtime or dynamic-linker–managed global initialization; PIE code must be robust without such assumptions.

3.  **Internal Dependencies Only**:
    *   You may ONLY use functions defined within this directory or provided by the Compel library headers.
    *   Look for helper functions in `compel/plugins/std` (e.g., `std_printf`, `std_memcpy`).

4.  **System Calls**:
    *   **Strictly forbid** libc wrappers (`printf`, `malloc`, `open`, etc.). Use raw system calls or CRIU helpers.
    *   **Use existing helpers**:
        *   Look for `sys_*` functions (e.g., `sys_write`, `sys_mmap`) declared in `compel/plugins/include/uapi/std/syscall.h` (or similar headers in `compel/include/uapi`).
        *   Implementation is often in `compel/arch/*/plugins/std/syscalls/`.
    *   **Adding a new syscall**:
        1.  Declare it in `compel/plugins/include/uapi/std/syscall.h` (or the relevant header).
        2.  Add the system call number and entry to the architecture-specific table: `compel/arch/<ARCH>/plugins/std/syscalls/syscall_<ARCH>.tbl`.
        3.  Reflect architecture differences if needed (e.g., different syscall numbers or calling conventions).

5.  **Stack Usage**:
    *   Be mindful of stack usage. This code often runs on a limited or borrowed stack.
    *   Avoid large stack allocations.
