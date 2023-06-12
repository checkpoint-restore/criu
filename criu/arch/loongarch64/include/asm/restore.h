#ifndef __CR_ASM_RESTORE_H__
#define __CR_ASM_RESTORE_H__

#include "asm/restorer.h"
#include "images/core.pb-c.h"

/* clang-format off */
#define JUMP_TO_RESTORER_BLOB(new_sp, restore_task_exec_start, task_args)	\
({										\
 	uint64_t save_sp;							\
	asm volatile("or %0, $zero, $sp" : "=r"(save_sp) : :"memory");		\
	asm volatile(								\
	        "or	$a0, $zero, %2	\n"					\
	        "or	$sp, $zero, %0	\n"					\
	        "jirl	$ra, %1, 0 	\n"					\
	        :                               				\
	        : "r"(new_sp & ~15),						\
	          "r"(restore_task_exec_start), 				\
	          "r"(task_args)						\
	        : "$a0", "memory");						\
	asm volatile("or $sp, $zero, %0" : : "r"(save_sp) : "memory"); 		\
})

/* clang-format on */

static inline void core_get_tls(CoreEntry *pcore, tls_t *ptls)
{
	*ptls = pcore->ti_loongarch64->tls;
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core);

#endif
