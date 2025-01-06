#ifndef __CR_ASM_COMPAT_H__
#define __CR_ASM_COMPAT_H__

#ifdef CR_NOGLIBC
#include <compel/plugins/std/syscall.h>
#include <compel/plugins/std/syscall-codes.h>
#else
#define sys_mmap   mmap
#define sys_munmap munmap
#endif

#include <sys/mman.h>

static inline void *alloc_compat_syscall_stack(void)
{
	void *mem = (void *)sys_mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_32BIT | MAP_ANONYMOUS | MAP_PRIVATE,
				     -1, 0);

	if ((uintptr_t)mem % PAGE_SIZE) {
		int err = (~(uint32_t)(uintptr_t)mem) + 1;

		pr_err("mmap() of compat syscall stack failed with %d\n", err);
		return 0;
	}
	return mem;
}

static inline void free_compat_syscall_stack(void *mem)
{
	long int ret = sys_munmap(mem, PAGE_SIZE);

	if (ret)
		pr_err("munmap() of compat addr %p failed with %ld\n", mem, ret);
}

struct syscall_args32 {
	uint32_t nr, arg0, arg1, arg2, arg3, arg4, arg5;
};

static inline uint32_t do_full_int80(struct syscall_args32 *args)
{
	/*
	 * Kernel older than v4.4 do not preserve r8-r15 registers when
	 * invoking int80, so we need to preserve them.
	 *
	 * Additionally, %rbp is used as the 6th syscall argument, and we need
	 * to preserve its value when returning from the syscall to avoid
	 * upsetting GCC. However, we can't use %rbp in the GCC asm clobbers
	 * due to a GCC limitation. Instead, we explicitly save %rbp on the
	 * stack before invoking the syscall and restore its value afterward.
	 *
	 * Further, GCC may not adjust the %rsp pointer when allocating the
	 * args and ret variables because 1) do_full_int80() is a leaf
	 * function, and 2) the local variables (args and ret) are in the
	 * 128-byte red-zone as defined in the x86_64 ABI. To use the stack
	 * when preserving %rbp, we must either tell GCC to a) mark the
	 * function as non-leaf, or b) move away from the red-zone when using
	 * the stack. It seems that there is no easy way to do a), so we'll go
	 * with b).
	 * Note 1: Another workaround would have been to add %rsp in the list
	 * of clobbers, but this was deprecated in GCC 9.
	 * Note 2: This red-zone bug only manifests when compiling CRIU with
	 * DEBUG=1.
	 */
	uint32_t ret;

	asm volatile("sub $128, %%rsp\n\t"
		     "pushq %%rbp\n\t"
		     "mov %7, %%ebp\n\t"
		     "int $0x80\n\t"
		     "popq %%rbp\n\t"
		     "add $128, %%rsp\n\t"
		     : "=a"(ret)
		     : "a"(args->nr), "b"(args->arg0), "c"(args->arg1), "d"(args->arg2), "S"(args->arg3),
		       "D"(args->arg4), "g"(args->arg5)
		     : "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15");
	return ret;
}

#ifndef CR_NOGLIBC
#undef sys_mmap
#undef sys_munmap
#endif

#endif
