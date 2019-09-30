#include <elf.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "compel/asm/fpu.h"
#include "compel/plugins/std/syscall-codes.h"
#include "cpu.h"
#include "kerndat.h"
#include "log.h"
#include "types.h"

#include "asm/compat.h"
#include "asm/dump.h"

int kdat_can_map_vdso(void)
{
	pid_t child;
	int stat;

	/*
	 * Running under fork so if vdso_64 is disabled - don't create
	 * it for criu accidentally.
	 */
	child = fork();
	if (child < 0) {
		pr_perror("%s(): failed to fork()", __func__);
		return -1;
	}

	if (child == 0) {
		int ret;

		ret = syscall(SYS_arch_prctl, ARCH_MAP_VDSO_32, 0);
		if (ret == 0)
			exit(1);
		/*
		 * Mapping vDSO while have not unmap it yet:
		 * this is restricted by API if ARCH_MAP_VDSO_* is supported.
		 */
		if (ret == -1 && errno == EEXIST)
			exit(1);
		exit(0);
	}

	if (waitpid(child, &stat, 0) != child) {
		pr_err("Failed to wait for arch_prctl() test\n");
		kill(child, SIGKILL);
		return -1;
	}

	if (!WIFEXITED(stat))
		return -1;

	return WEXITSTATUS(stat);

}

#ifdef CONFIG_COMPAT
void *mmap_ia32(void *addr, size_t len, int prot,
		int flags, int fildes, off_t off)
{
	struct syscall_args32 s;

	s.nr    = __NR32_mmap2;
	s.arg0  = (uint32_t)(uintptr_t)addr;
	s.arg1  = (uint32_t)len;
	s.arg2  = prot;
	s.arg3  = flags;
	s.arg4  = fildes;
	s.arg5  = (uint32_t)off;

	return (void *)(uintptr_t)do_full_int80(&s);
}

/*
 * The idea of the test:
 * From kernel's top-down allocator we assume here that
 * 1. A = mmap(0, ...); munmap(A);
 * 2. B = mmap(0, ...);
 * results in A == B.
 * ...but if we have 32-bit mmap() bug, then A will have only lower
 * 4 bytes of 64-bit address allocated with mmap().
 * That means, that the next mmap() will return B != A
 * (as munmap(A) hasn't really unmapped A mapping).
 *
 * As mapping with lower 4 bytes of A may really exist, we run
 * this test under fork().
 *
 * Another approach to test bug's presence would be to parse
 * /proc/self/maps before and after 32-bit mmap(), but that would
 * be soo slow.
 */
static void mmap_bug_test(void)
{
	void *map1, *map2;
	int err;

	map1 = mmap_ia32(0, PAGE_SIZE, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	/* 32-bit error, not sign-extended - can't use IS_ERR_VALUE() here */
	err = (uintptr_t)map1 % PAGE_SIZE;
	if (err) {
		pr_err("ia32 mmap() failed: %d\n", err);
		exit(1);
	}

	if (munmap(map1, PAGE_SIZE)) {
		pr_err("Failed to unmap() 32-bit mapping: %m\n");
		exit(1);
	}

	map2 = mmap_ia32(0, PAGE_SIZE, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	err = (uintptr_t)map2 % PAGE_SIZE;
	if (err) {
		pr_err("ia32 mmap() failed: %d\n", err);
		exit(1);
	}

	if (map1 != map2)
		exit(1);
	exit(0);
}

/*
 * Pre v4.12 kernels have a bug: for a process started as 64-bit
 * 32-bit mmap() may return 8 byte pointer.
 * Which is fatal for us: after 32-bit C/R a task will map 64-bit
 * addresses, cut upper 4 bytes and try to use lower 4 bytes.
 * This is a check if the bug was fixed in the kernel.
 */
static int has_32bit_mmap_bug(void)
{
	pid_t child = fork();
	int stat;

	if (child < 0) {
		pr_perror("%s(): failed to fork()", __func__);
		return -1;
	}

	if (child == 0)
		mmap_bug_test();

	if (waitpid(child, &stat, 0) != child) {
		pr_err("Failed to wait for mmap test\n");
		kill(child, SIGKILL);
		return -1;
	}

	if (!WIFEXITED(stat) || WEXITSTATUS(stat) != 0)
		return 1;
	return 0;
}

int kdat_compatible_cr(void)
{
	if (!kdat.can_map_vdso)
		return 0;

	if (has_32bit_mmap_bug())
		return 0;

	return 1;
}
#else /* !CONFIG_COMPAT */
int kdat_compatible_cr(void)
{
	return 0;
}
#endif

static int kdat_x86_has_ptrace_fpu_xsave_bug_child(void *arg)
{
	if (ptrace(PTRACE_TRACEME, 0, 0, 0)) {
		pr_perror("%d: ptrace(PTRACE_TRACEME) failed", getpid());
		_exit(1);
	}

	if (kill(getpid(), SIGSTOP))
		pr_perror("%d: failed to kill myself", getpid());

	pr_err("Continue after SIGSTOP.. Urr what?\n");
	_exit(1);
}

/*
 * Pre v4.14 kernels have a bug on Skylake CPUs:
 * copyout_from_xsaves() creates fpu state for
 *   ptrace(PTRACE_GETREGSET, pid, NT_X86_XSTATE, &iov)
 * without MXCSR and MXCSR_FLAGS if there is SSE/YMM state, but no FP state.
 * That is xfeatures had either/both XFEATURE_MASK_{SSE,YMM} set, but not
 * XFEATURE_MASK_FP.
 * But we *really* need to C/R MXCSR & MXCSR_FLAGS if SSE/YMM active,
 * as mxcsr store part of the state.
 */
int kdat_x86_has_ptrace_fpu_xsave_bug(void)
{
	user_fpregs_struct_t xsave = { };
	struct iovec iov;
	char stack[PAGE_SIZE];
	int flags = CLONE_VM | CLONE_FILES | CLONE_UNTRACED | SIGCHLD;
	int ret = -1;
	pid_t child;
	int stat;

	/* OSXSAVE can't be changed during boot. */
	if (!compel_cpu_has_feature(X86_FEATURE_OSXSAVE))
		return 0;

	child = clone(kdat_x86_has_ptrace_fpu_xsave_bug_child,
		stack + ARRAY_SIZE(stack), flags, 0);
	if (child < 0) {
		pr_perror("%s(): failed to clone()", __func__);
		return -1;
	}

	if (waitpid(child, &stat, WUNTRACED) != child) {
		/*
		 * waitpid() may end with ECHILD if SIGCHLD == SIG_IGN,
		 * and the child has stopped already.
		 */
		pr_perror("Failed to wait for %s() test\n", __func__);
		goto out_kill;
	}

	if (!WIFSTOPPED(stat)) {
		pr_err("Born child is unstoppable! (might be dead)\n");
		goto out_kill;
	}

	iov.iov_base = &xsave;
	iov.iov_len = sizeof(xsave);

	if (ptrace(PTRACE_GETREGSET, child, (unsigned)NT_X86_XSTATE, &iov) < 0) {
		pr_perror("Can't obtain FPU registers for %d", child);
		goto out_kill;
	}
	/*
	 * MXCSR should be never 0x0: e.g., it should contain either:
	 * R+/R-/RZ/RN to determine rounding model.
	 */
	ret = !xsave.i387.mxcsr;

out_kill:
	if (kill(child, SIGKILL))
		pr_perror("Failed to kill my own child");
	if (waitpid(child, &stat, 0) < 0)
		pr_perror("Failed wait for a dead child");

	return ret;
}
