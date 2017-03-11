#include "log.h"
#include "asm/restorer.h"
#include <compel/asm/fpu.h>
#include "asm/compat.h"

#ifdef CR_NOGLIBC
# include <compel/plugins/std/syscall.h>
# include <compel/plugins/std/string.h>
#else
# ifndef  __NR32_rt_sigaction
#  define  __NR32_rt_sigaction 174
# endif
#endif
#include "cpu.h"

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
	memcpy(stack32, act, sizeof(rt_sigaction_t_compat));

	asm volatile ("\t movl %%ebx,%%ebx\n" : :"b"(sig));	/* signum */
	asm volatile ("\t movl %%ecx,%%ecx\n" : :"c"(stack32));	/* act */
	asm volatile ("\t movl %%edx,%%edx\n" : :"d"(sizeof(act->rt_sa_mask)));
	call32_from_64(stack32 + PAGE_SIZE, &restore_rt_sigaction);
	asm volatile ("\t movl %%eax,%0\n" : "=r"(ret));
	return ret;
}

