#ifndef __CR_ASM_RESTORE_H__
#define __CR_ASM_RESTORE_H__

#include "asm/restorer.h"

#include "protobuf/core.pb-c.h"

/*
 * Set R2 to blob + 8000 which is the default value
 * Jump to restore_task_exec_start + 8 since R2 is already set (local call)
 */
#define JUMP_TO_RESTORER_BLOB(new_sp, restore_task_exec_start,		\
			      task_args)				\
	asm volatile(							\
		"mr	1,%0		\n"				\
		"mr	3,%1		\n"				\
		"mtctr	3		\n"				\
		"mr   	3,%2		\n"				\
	        "mr	2,%3		\n"				\
		"bctr			\n"				\
		:							\
		: "r"(new_sp),						\
		  "r"((unsigned long)restore_task_exec_start),		\
		  "r"(task_args),					\
		  "r"((unsigned long)task_args->bootstrap_start + 0x8000) \
		: "sp", "1", "2", "3", "memory")

/* There is nothing to do since TLS is accessed through r13 */
#define core_get_tls(pcore, ptls)

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core);

#define arch_export_restore_task	__export_restore_task_trampoline
#define arch_export_unmap		__export_unmap_trampoline

#endif /* __CR_ASM_RESTORE_H__ */
