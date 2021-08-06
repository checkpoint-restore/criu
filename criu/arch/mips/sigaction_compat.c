#include "asm/compat.h"
#include "asm/restorer.h"
#include "log.h"
#include <compel/asm/fpu.h>
#include <compel/plugins/std/syscall-codes.h>

#ifdef CR_NOGLIBC
#include <compel/plugins/std/string.h>
#endif

#include "cpu.h"

extern char restore_rt_sigaction;

int arch_compat_rt_sigaction(void *stack32, int sig, rt_sigaction_t_compat *act)
{
	return 0;
}
