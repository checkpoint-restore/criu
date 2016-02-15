#ifndef __CR_ASM_DUMP_H__
#define __CR_ASM_DUMP_H__

extern int get_task_regs(pid_t pid, user_regs_struct_t regs, CoreEntry *core);
extern int arch_alloc_thread_info(CoreEntry *core);
extern void arch_free_thread_info(CoreEntry *core);


#define core_put_tls(core, tls)

#endif
