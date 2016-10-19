#ifndef __CR_ASM_DUMP_H__
#define __CR_ASM_DUMP_H__

extern int save_task_regs(void *, user_regs_struct_t *, user_fpregs_struct_t *);
extern int arch_alloc_thread_info(CoreEntry *core);
extern void arch_free_thread_info(CoreEntry *core);


#define core_put_tls(core, tls)

#endif
