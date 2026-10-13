# Security Considerations for Running Workloads

## Overview

To ensure the security and integrity of processes checkpointed and restored by
CRIU, workloads should be configured with certain security restrictions. This
document provides advice on how to run workloads safely to prevent potential
security vulnerabilities during checkpoint and restore operations.

## Recommended Configurations

### 1. Restrict `CLONE_VM` without `CLONE_THREAD`

**Risk:** CRIU's dump mechanism relies on injecting and executing **parasite
code** directly within the address space of the seized processes. The security
and correctness of this parasite code rely heavily on the fundamental assumption
that **all users (threads or processes) sharing the current virtual memory
(VM/mm_struct) are stopped**.

A critical security vulnerability arises if there are running tasks that
share the same virtual memory but are **not stopped** by CRIU.

This situation occurs when a workload creates a new process using the `CLONE_VM`
flag but **without** the `CLONE_THREAD` flag. This creates a separate process
(with its own PID and thread group) that shares the `mm_struct` of the parent.

If CRIU is instructed to dump a specific process tree (subtree) and this related
process is outside that tree, CRIU will not be aware of it and will not stop it.

This unstopped process continues to run concurrently with the parasite
code. Because it shares the same virtual memory, it can:

*   **Tamper with Parasite Execution:** Modify memory used by the parasite code.
*   **Corrupt Dumped State:** Modify process properties or memory content while
    CRIU is capturing them.
*   **Facilitate Privilege Escalation:** Manipulate security-critical state
    (like credentials or registers) in memory just before they are serialized,
    leading to corrupted state upon restoration.

> [!NOTE]
> This specific risk of an unstopped process escaping detection primarily
> exists when dumping a specific process tree (subtree) rather than an entire
> isolated PID namespace. If CRIU is dumping an entire container running in
> its own dedicated PID namespace, all processes within that namespace are
> discovered and frozen. In this scenario, the risk is eliminated because the
> related process cannot escape the namespace boundary. However, restricting
> `CLONE_VM` without `CLONE_THREAD` remains a good defense-in-depth practice.

**Mitigation:**
Restrict or audit the use of `CLONE_VM` without `CLONE_THREAD`. For untrusted
workloads, consider using seccomp filters to block `clone()` calls that
attempt to share memory without being part of the same thread group.

> [!IMPORTANT]
> When using seccomp to filter system call arguments, the `clone3()` system
> call should be **blocked entirely**. Seccomp cannot safely inspect arguments
> passed via pointers to memory (like the `struct clone_args` in `clone3`),
> making it impossible to reliably filter flags within `clone3()`. Any
> validation must rely on standard `clone()`.
