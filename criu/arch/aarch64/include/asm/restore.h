#ifndef __CR_ASM_RESTORE_H__
#define __CR_ASM_RESTORE_H__

#include "asm/restorer.h"

#include "images/core.pb-c.h"

#define JUMP_TO_RESTORER_BLOB(new_sp, restore_task_exec_start,	\
			      task_args)			\
	asm volatile(						\
			"and  sp, %0, #~15		\n"	\
			"mov  x0, %2			\n"	\
			"br   %1			\n"	\
			:					\
			: "r"(new_sp),				\
			  "r"(restore_task_exec_start),		\
			  "r"(task_args)			\
			: "sp", "x0", "memory")

static inline void core_get_tls(CoreEntry *pcore, tls_t *ptls)
{
	*ptls = pcore->ti_aarch64->tls;
}


int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core);

#endif
