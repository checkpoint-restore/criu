#ifndef __CR_ASM_DUMP_H__
#define __CR_ASM_DUMP_H__

extern int get_task_regs(pid_t pid, CoreEntry *core, const struct parasite_ctl *ctl);
extern int arch_alloc_thread_info(CoreEntry *core);

#endif
