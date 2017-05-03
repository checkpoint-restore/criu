#ifndef __CR_ASM_DUMP_H__
#define __CR_ASM_DUMP_H__

extern int save_task_regs(void *, user_regs_struct_t *, user_fpregs_struct_t *);
extern int arch_alloc_thread_info(CoreEntry *core);
extern void arch_free_thread_info(CoreEntry *core);
extern int get_task_futex_robust_list_compat(pid_t pid, ThreadCoreEntry *info);

static inline void core_put_tls(CoreEntry *core, tls_t tls)
{
	ThreadInfoX86 *ti = core->thread_info;
	int i;

	for (i = 0; i < GDT_ENTRY_TLS_NUM; i++)
	{
		user_desc_t *from = &tls.desc[i];
		UserDescT *to = ti->tls[i];

#define COPY_TLS(field) to->field = from->field
		COPY_TLS(entry_number);
		COPY_TLS(base_addr);
		COPY_TLS(limit);
		COPY_TLS(seg_32bit);
		to->contents_h = from->contents & 0x2;
		to->contents_l = from->contents & 0x1;
		COPY_TLS(read_exec_only);
		COPY_TLS(limit_in_pages);
		COPY_TLS(seg_not_present);
		COPY_TLS(useable);
#undef COPY_TLS
	}
}

#endif
