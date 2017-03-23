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

#ifdef CONFIG_COMPAT
extern unsigned long call32_from_64(void *stack, void *func);
#endif

#ifndef CR_NOGLIBC
# undef sys_mmap
# undef sys_munmap
#endif

#endif
