#ifndef __CR_ASM_RESTORE_H__
#define __CR_ASM_RESTORE_H__

#include "asm/restorer.h"

#include "images/core.pb-c.h"

/* clang-format off */
#define JUMP_TO_RESTORER_BLOB(new_sp, restore_task_exec_start,		\
			      task_args)				\
	asm volatile(							\
		     "movq %0, %%rbx				    \n" \
		     "movq %1, %%rax				    \n" \
		     "movq %2, %%rdi				    \n" \
		     "movq %%rbx, %%rsp				    \n"	\
		     "callq *%%rax				    \n" \
		     :							\
		     : "g"(new_sp),					\
		       "g"(restore_task_exec_start),			\
		       "g"(task_args)					\
		     : "rdi", "rsi", "rbx", "rax", "memory")
/* clang-format on */

static inline void core_get_tls(CoreEntry *pcore, tls_t *ptls)
{
	ThreadInfoX86 *ti = pcore->thread_info;
	size_t i;

	for (i = 0; i < GDT_ENTRY_TLS_NUM; i++) {
		user_desc_t *to = &ptls->desc[i];
		UserDescT *from;

		/*
		 * If proto image has lesser TLS entries,
		 * mark them as not present (and thus skip restore).
		 */
		if (i >= ti->n_tls) {
			to->seg_not_present = 1;
			continue;
		}

		from = ti->tls[i];
#define COPY_TLS(field) to->field = from->field
		COPY_TLS(entry_number);
		COPY_TLS(base_addr);
		COPY_TLS(limit);
		COPY_TLS(seg_32bit);
		to->contents = ((u32)from->contents_h << 1) | from->contents_l;
		COPY_TLS(read_exec_only);
		COPY_TLS(limit_in_pages);
		COPY_TLS(seg_not_present);
		COPY_TLS(usable);
#undef COPY_TLS
	}
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core);

#endif
