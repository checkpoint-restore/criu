#ifndef __CR_CGROUP_H__
#define __CR_CGROUP_H__
#include "asm/int.h"
struct pstree_item;
int dump_task_cgroup(struct pstree_item *, u32 *);
int dump_cgroups(void);
#endif /* __CR_CGROUP_H__ */
