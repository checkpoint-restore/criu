#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <asm-generic/ucontext.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Checkpoint proc that is intercepting syscalls in a busy-loop.";
const char *test_author = "Svetly Todorov <svetly.todorov@memverge.com>";

#ifdef PR_SET_SYSCALL_USER_DISPATCH

void __attribute__((noplt, used)) sud_begin(void);
__asm__(
    "sud_begin:\n\t"
    "nop\n\t");

long syscall_passthrough(long number, ...) {
    long arg1;
    long arg2;
    long arg3;
    long arg4;
    long arg5;
    long arg6;
    
    long result;

    va_list args;
    va_start(args, number);

    // Extract the syscall arguments
    arg1 = va_arg(args, long);
    arg2 = va_arg(args, long);
    arg3 = va_arg(args, long);
    arg4 = va_arg(args, long);
    arg5 = va_arg(args, long);
    arg6 = va_arg(args, long);

    va_end(args);

    __asm__ __volatile__ (
        "mov %1, %%rax\n" // syscall number
        "mov %2, %%rdi\n" // arg1
        "mov %3, %%rsi\n" // arg2
        "mov %4, %%rdx\n" // arg3
        "mov %5, %%r10\n" // arg4
        "mov %6, %%r8\n"  // arg5
        "mov %7, %%r9\n"  // arg6
        "syscall\n"
        "mov %%rax, %0\n" // result
        : "=r" (result)
        : "r" (number), "r" (arg1), "r" (arg2), "r" (arg3), "r" (arg4), "r" (arg5), "r" (arg6)
        : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"
    );

    return result;
}

// This operation tests that the value at the futex word
// pointed to by the address uaddr still contains the
// expected value val, and if so, then sleeps waiting for a
// FUTEX_WAKE operation on the futex word.
long sys_futex_wait(uint32_t *uaddr, uint32_t val) {
    return syscall_passthrough(SYS_futex, uaddr, FUTEX_WAIT, val, NULL, NULL, 0);
}

// This operation wakes at most val of the waiters that are
// waiting (e.g., inside FUTEX_WAIT) on the futex word at the
// address uaddr.
long sys_futex_wake_all(uint32_t *uaddr) {
    return syscall_passthrough(SYS_futex, uaddr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
}

int sys_msync(void *addr, size_t length, int flags) {
    return syscall_passthrough(SYS_msync, addr, length, flags);
}

void __attribute__((noplt, used)) sud_end(void);
__asm__(
    "sud_end:\n\t"
    "nop\n\t");

// u32 futex word
uint32_t *word;

// counter for SIGSYS handler
volatile int counter;

// selector for SUD
volatile char selector;

// SUD causes SIGSYS when a syscall instruction is encountered.
// We catch the SIGSYS and enter this handler.
void sigsys_handler(int signo, siginfo_t *si, void *ucontext)
{
    struct ucontext *ctxt = (struct ucontext *)ucontext;

    // rax holds the return code on x86-64
    ctxt->uc_mcontext.rax = 0;

    // Increment sigsys counter
    counter += 1;
    // Allow syscalls, so that rt_sigreturn doesn't cause a panic
    selector = SYSCALL_DISPATCH_FILTER_ALLOW;

    // Alias for rt_sigreturn()
    return;
}

int main(int argc, char **argv)
{
    int status, rc;
    pid_t pid;

    test_init(argc, argv);
    
    // Initialize futex

	word = mmap(NULL, sizeof(*word), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

	if (word == MAP_FAILED) {
		pr_perror("mmap failed");
		exit(1);
	}

    *word = 0;

    pid = fork();
    if (pid < 0) {
		pr_perror("fork");
		return -1;
	}

    if (pid == 0) {
        struct timespec ts;
        struct sigaction sa;

        // Initialize SIGSYS counter

        counter = 0;

        // Register the sigsys handler

        sa.sa_sigaction = sigsys_handler;
        sa.sa_flags = SA_SIGINFO;

        if (sigaction(SIGSYS, &sa, NULL)) {
            pr_perror("sigaction");
            exit(1);
        }

        test_msg("Child proc registered sigaction.\n");

        // Activate syscall dispatch, excluding the futex syscalls

        selector = SYSCALL_DISPATCH_FILTER_BLOCK;

        if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, &sud_begin, (uint64_t)&sud_end - (uint64_t)&sud_begin, &selector)) {
            pr_perror("prctl");
            exit(1);
        }

        // Tell the parent we're ready for snapshot

        *word = 1;

        sys_msync(word, sizeof(*word), MS_SYNC | MS_INVALIDATE);

        sys_futex_wake_all(word);

        // Wait for parent to do the snapshot

        while (*word == 1)
            sys_futex_wait(word, 1);

        // Now do an unsafe syscall

        if (syscall(SYS_clock_gettime, CLOCK_REALTIME, &ts, NULL)) {
            selector = SYSCALL_DISPATCH_FILTER_ALLOW;
            exit(2);
        }

        test_msg("Child proc SIGSYS handler counter: %d.\n", counter);

        if (counter != 1)
            exit(3);

        exit(0);
    }

    // Parent waits until child sets the futex word to nonzero

    while (*word == 0)
        sys_futex_wait(word, 0);

    test_msg("Parent proc snapshotting.\n");

    test_daemon();
    test_waitsig();

    test_msg("Parent proc exited waitsig. Entering waitPID.\n");

    // Set the futex to 2 and wake up the child

    *word = 2;

    sys_msync(word, sizeof(*word), MS_SYNC | MS_INVALIDATE);

    sys_futex_wake_all(word);

    // Now wait for the child to exit

	rc = waitpid(pid, &status, 0);
	if (rc != pid) {
		fail("waitpid: %d != %d", rc, pid);
		exit(1);
	}

    test_msg("Parent proc exited waitPID.\n");

    // If child exited with nonzero then we will fail the test here

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fail("expected 0 exit, got %d", WEXITSTATUS(status));
		exit(1);
	}

    pass();
    return 0;
}

#else /* PR_SET_SYCALL_USER_DISPATCH */

#define TEST_SKIP_REASON "incompatible kernel (prctl cannot set SUD)"
#include "skip-me.c"

#endif /* PR_SET_SYCALL_USER_DISPATCH */