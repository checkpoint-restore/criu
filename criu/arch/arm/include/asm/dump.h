#ifndef __CR_ASM_DUMP_H__
#define __CR_ASM_DUMP_H__

extern int save_task_regs(void *, user_regs_struct_t *, user_fpregs_struct_t *);
extern int arch_alloc_thread_info(CoreEntry *core);
extern void arch_free_thread_info(CoreEntry *core);

static inline void core_put_tls(CoreEntry *core, tls_t tls)
{
	core->ti_arm->tls = tls;
}

#define get_task_futex_robust_list_compat(pid, info) -1

#endif
