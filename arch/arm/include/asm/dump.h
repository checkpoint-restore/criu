#ifndef __CR_ASM_DUMP_H__
#define __CR_ASM_DUMP_H__

extern int get_task_regs(pid_t pid, CoreEntry *core, const struct parasite_ctl *ctl);
extern int arch_alloc_thread_info(CoreEntry *core);
extern void core_entry_free(CoreEntry *core);


static inline void core_put_tls(CoreEntry *core, u32 tls)
{
	core->ti_arm->tls = tls;
}

#endif
