#include "log.h"
#include "asm/restorer.h"
#include <compel/asm/fpu.h>
#include "asm/compat.h"
#include <compel/plugins/std/syscall-codes.h>

#ifdef CR_NOGLIBC
# include <compel/plugins/std/string.h>
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
	struct syscall_args32 arg = {};
	unsigned long act_stack = (unsigned long)stack32;

	/* To make sure the 32-bit stack was allocated in caller */
	if (act_stack >= (uint32_t)-1) {
		pr_err("compat rt_sigaction without 32-bit stack\n");
		return -1;
	}

	/*
	 * To be sure, that sigaction pointer lies under 4G,
	 * coping it on the bottom of the stack.
	 */
	memcpy(stack32, act, sizeof(rt_sigaction_t_compat));
	arg.nr		= __NR32_rt_sigaction;
	arg.arg0	= sig;
	arg.arg1	= (uint32_t)act_stack;			/* act */
	arg.arg2	= 0;					/* oldact */
	arg.arg3	= (uint32_t)sizeof(act->rt_sa_mask);	/* sigsetsize */

	return do_full_int80(&arg);
}
