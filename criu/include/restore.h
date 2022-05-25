#ifndef __CR_INC_RESTORE_H__
#define __CR_INC_RESTORE_H__

#include "pid.h"
#include "types.h"
#include "asm/restore.h"

extern int arch_set_thread_regs_nosigrt(struct pid *pid);

struct task_restore_args;
struct pstree_item;

#ifndef arch_shstk_prepare
static inline int arch_shstk_prepare(struct pstree_item *item,
				     CoreEntry *core,
				     struct task_restore_args *ta)
{
	return 0;
}
#define arch_shstk_prepare arch_shstk_prepare
#endif

#endif
