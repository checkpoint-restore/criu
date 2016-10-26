#ifndef __CR_ASM_RESTORE_H__
#define __CR_ASM_RESTORE_H__

#include "asm/restorer.h"

#include "images/core.pb-c.h"

/*
 * Set R2 to blob + 8000 which is the default value
 * Jump to restore_task_exec_start + 8 since R2 is already set (local call)
 */
#define JUMP_TO_RESTORER_BLOB(new_sp, restore_task_exec_start,		\
			      task_args)				\
	asm volatile(							\
		"mr	1,%0		\n"				\
		"mr	12,%1		\n"				\
		"mtctr	12		\n"				\
		"mr   	3,%2		\n"				\
		"bctr			\n"				\
		:							\
		: "r"(new_sp),						\
		  "r"((unsigned long)restore_task_exec_start),		\
		  "r"(task_args)					\
		: "r1", "1", "2", "3", "12", "memory")

/* There is nothing to do since TLS is accessed through r13 */
#define core_get_tls(pcore, ptls)

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core);

#endif /* __CR_ASM_RESTORE_H__ */
