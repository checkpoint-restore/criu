#ifndef __CR_ASM_DUMP_H__
#define __CR_ASM_DUMP_H__

int save_task_regs(void *arg, user_regs_struct_t *u, user_fpregs_struct_t *f);
int arch_alloc_thread_info(CoreEntry *core);
void arch_free_thread_info(CoreEntry *core);

static inline void core_put_tls(CoreEntry *core, tls_t tls)
{
}

#define get_task_futex_robust_list_compat(pid, info) -1

#endif
