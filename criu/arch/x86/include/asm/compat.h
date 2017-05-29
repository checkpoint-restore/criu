#ifndef __CR_ASM_COMPAT_H__
#define __CR_ASM_COMPAT_H__

#ifdef CR_NOGLIBC
# include <compel/plugins/std/syscall.h>
# include <compel/plugins/std/syscall-codes.h>
#else
# define sys_mmap mmap
# define sys_munmap munmap
#endif

#include <sys/mman.h>

static inline void *alloc_compat_syscall_stack(void)
{
	void *mem = (void*)sys_mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			MAP_32BIT | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

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
		pr_err("munmap() of compat addr %p failed with %ld\n",
				mem, ret);
}

struct syscall_args32 {
	uint32_t nr, arg0, arg1, arg2, arg3, arg4, arg5;
};

static inline void do_full_int80(struct syscall_args32 *args)
{
	/*
	 * r8-r11 registers are cleared during returning to userspace
	 * from syscall - that's x86_64 ABI to avoid leaking kernel
	 * pointers.
	 *
	 * Other than that - we can't use %rbp in clobbers as GCC's inline
	 * assembly doesn't allow to do so. So, here is explicitly saving
	 * %rbp before syscall and restoring it's value afterward.
	 */
	asm volatile ("pushq %%rbp\n\t"
			"mov %6, %%ebp\n\t"
			"int $0x80\n\t"
			"mov %%ebp, %6\n\t"
			"popq %%rbp\n\t"
		      : "+a" (args->nr),
			"+b" (args->arg0), "+c" (args->arg1), "+d" (args->arg2),
			"+S" (args->arg3), "+D" (args->arg4), "+g" (args->arg5)
			: : "r8", "r9", "r10", "r11");
}


#ifdef CONFIG_COMPAT
extern unsigned long call32_from_64(void *stack, void *func);
#endif

#ifndef CR_NOGLIBC
# undef sys_mmap
# undef sys_munmap
#endif

#endif
