#ifndef __CR_ASM_RESTORE_H__
#define __CR_ASM_RESTORE_H__

#include "asm/restorer.h"

#include "images/core.pb-c.h"

/* clang-format off */
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
			: "x0", "memory")
/* clang-format on */

static inline void core_get_tls(CoreEntry *pcore, tls_t *ptls)
{
	*ptls = pcore->ti_aarch64->tls;
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core);

#define ARCH_RST_INFO y
struct rst_arch_info {
	bool has_paca, has_pacg;
	PacAddressKeys pac_address_keys;
	PacGenericKeys pac_generic_keys;
};

int arch_ptrace_restore(int pid, struct pstree_item *item);
void arch_rsti_init(struct pstree_item *current);

#endif
