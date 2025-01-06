#ifndef __CR_ASM_RESTORE_H__
#define __CR_ASM_RESTORE_H__

#include "asm/restorer.h"
#include "images/core.pb-c.h"

/* clang-format off */
#define JUMP_TO_RESTORER_BLOB(new_sp, restore_task_exec_start, task_args) \
	asm volatile(							\
		"move $4, %0					\n"	\
		"move $25, %1 					\n"	\
		"move $5, %2					\n"	\
		"move $29, $5					\n"	\
		"jalr $25   					\n"	\
		"nop   						\n"	\
		:							\
		:"r"(task_args),"r"(restore_task_exec_start),		\
		 "g"(new_sp)						\
		: "$25", "$4","$5")
/* clang-format on */

static inline void core_get_tls(CoreEntry *pcore, tls_t *ptls)
{
	*ptls = pcore->ti_mips->tls;
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core);

#endif
