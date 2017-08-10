#ifndef __CR_ASM_RESTORE_H__
#define __CR_ASM_RESTORE_H__

#include "asm/restorer.h"

#include "images/core.pb-c.h"
/*
 * Load stack to %r15, return address in %r14 and argument 1 into %r2
 */
#define JUMP_TO_RESTORER_BLOB(new_sp, restore_task_exec_start,		\
			      task_args)				\
	asm volatile(							\
		"lgr	%%r15,%0\n"					\
		"lgr	%%r14,%1\n"					\
		"lgr	%%r2,%2\n"					\
		"basr	%%r14,%%r14\n"					\
		:							\
		: "d" (new_sp),						\
		  "d"((unsigned long)restore_task_exec_start),		\
		  "d" (task_args)					\
		: "2", "14", "15", "memory")

/* There is nothing to do since TLS is accessed through %a01 */
#define core_get_tls(pcore, ptls)

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core);
#endif
