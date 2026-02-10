---
applyTo: "**/{pie,compel}/**/*.{c,h}"
---
# Copilot Instructions for PIE (Position Independent Executable) Code

The code in this directory is compiled as Position Independent Executable (PIE) and is often injected into target processes as "parasite" code.
This environment is extremely restrictive.

## Critical Constraints

1.  **No External Libraries**:
    *   Do **NOT** use functionality from standard libraries (NO `libc`, `pthread`, `printf`, `malloc`, etc.).
    *   The code must be completely self-contained.

2.  **No Global State**:
    *   Avoid global variables that require relocation or initialization by the dynamic linker.
    *   Read-only globals (`const`) are generally safe if they don't contain pointers to other globals.

3.  **Internal Dependencies Only**:
    *   You may ONLY use functions defined within this directory or provided by the Compel library headers.
    *   Look for helper functions in `compel/plugins/std` (e.g., `std_printf`, `std_memcpy`).

4.  **System Calls**:
    *   Use raw system calls for all OS interactions.
    *   Do not rely on glibc wrappers.
    *   Use the provided syscall wrappers (e.g., `sys_write`, `sys_mmap`) if available in the headers.

5.  **Stack Usage**:
    *   Be mindful of stack usage. This code often runs on a limited or borrowed stack.
    *   Avoid large stack allocations.
