#ifndef __CR_ASM_RESTORE_H__
#define __CR_ASM_RESTORE_H__

#include "asm/restorer.h"

#include "images/core.pb-c.h"

/* clang-format off */
#define JUMP_TO_RESTORER_BLOB(new_sp, restore_task_exec_start,		\
			      task_args)				\
	asm volatile(							\
		     "mov sp, %0				    \n" \
		     "mov r1, %1				    \n" \
		     "mov r0, %2				    \n" \
		     "bx  r1					    \n"	\
		     :							\
		     : "r"(new_sp),					\
		       "r"(restore_task_exec_start),			\
		       "r"(task_args)					\
		     : "r0", "r1", "memory")
/* clang-format on */

static inline void core_get_tls(CoreEntry *pcore, tls_t *ptls)
{
	*ptls = pcore->ti_arm->tls;
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core);

#endif
