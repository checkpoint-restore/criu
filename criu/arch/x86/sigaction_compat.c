#include "asm/restorer.h"
#include <compel/asm/fpu.h>
#include "asm/string.h"

#include <sys/mman.h>

#ifdef CR_NOGLIBC
# include <compel/plugins/std/syscall.h>
#else
# define sys_mmap mmap
# define sys_munmap munmap
# ifndef  __NR32_rt_sigaction
#  define  __NR32_rt_sigaction 174
# endif
#endif
#include "log.h"
#include "cpu.h"

void *alloc_compat_syscall_stack(void)
{
	void *mem = (void*)sys_mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			MAP_32BIT | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (mem == MAP_FAILED)
		return 0;
	return mem;
}

void free_compat_syscall_stack(void *mem)
{
	sys_munmap(mem, PAGE_SIZE);
}

asm (	"	.pushsection .text				\n"
	"	.global restore_rt_sigaction			\n"
	"	.code32						\n"
	"restore_rt_sigaction:					\n"
	"	mov %edx, %esi					\n"
	"	mov $0, %edx					\n"
	"	movl $"__stringify(__NR32_rt_sigaction)",%eax	\n"
	"	int $0x80					\n"
	"	ret						\n"
	"	.popsection					\n"
	"	.code64");
extern char restore_rt_sigaction;

/*
 * Call raw rt_sigaction syscall through int80 - so the ABI kernel choses
 * to deliver this signal would be i386.
 */
int arch_compat_rt_sigaction(void *stack32, int sig, rt_sigaction_t_compat *act)
{
	int ret;

	/*
	 * To be sure, that sigaction pointer lies under 4G,
	 * coping it on the bottom of the stack.
	 */
	builtin_memcpy(stack32, act, sizeof(rt_sigaction_t_compat));

	asm volatile ("\t movl %%ebx,%%ebx\n" : :"b"(sig));	/* signum */
	asm volatile ("\t movl %%ecx,%%ecx\n" : :"c"(stack32));	/* act */
	asm volatile ("\t movl %%edx,%%edx\n" : :"d"(sizeof(act->rt_sa_mask)));
	call32_from_64(stack32 + PAGE_SIZE, &restore_rt_sigaction);
	asm volatile ("\t movl %%eax,%0\n" : "=r"(ret));
	return ret;
}

