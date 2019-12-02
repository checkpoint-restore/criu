/*fixme: gysun */
//#include <asm/prctl.h>
#include <unistd.h>

#include "types.h"
#include "restorer.h"
#include "asm/compat.h"
#include "asm/restorer.h"
#include <compel/asm/fpu.h>

#include <compel/plugins/std/syscall-codes.h>
#include <compel/plugins/std/string.h>
#include <compel/plugins/std/syscall.h>
#include "log.h"
#include "cpu.h"

int restore_nonsigframe_gpregs(UserMipsRegsEntry *r)
{
	return 0;
}

#ifdef CONFIG_COMPAT

int set_compat_robust_list(uint32_t head_ptr, uint32_t len)
{
	struct syscall_args32 s = {
		.nr	= __NR32_set_robust_list,
		.arg0	= head_ptr,
		.arg1	= len,
	};

	do_full_int80(&s);
	return (int)s.nr;
}

static int prepare_stack32(void **stack32)
{
	if (*stack32)
		return 0;

	*stack32 = alloc_compat_syscall_stack();
	if (!*stack32) {
		pr_err("Failed to allocate stack for 32-bit TLS restore\n");
		return -1;
	}

	return 0;
}

void restore_tls(tls_t *ptls)
{
	asm volatile(							
		     "move $4, %0				    \n"	
		     "li $2,  "__stringify(__NR_set_thread_area)"  \n" 
		     "syscall					    \n"	
		     :							
		     : "r"(*ptls)					
		     : "$4","$2","memory");
}
#endif
