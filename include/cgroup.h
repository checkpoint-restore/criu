#ifndef __CR_CGROUP_H__
#define __CR_CGROUP_H__
#include "asm/int.h"
struct pstree_item;
extern u32 root_cg_set;
int dump_task_cgroup(struct pstree_item *, u32 *);
int dump_cgroups(void);
int prepare_task_cgroup(struct pstree_item *);
int prepare_cgroup(void);
void fini_cgroup(void);
#endif /* __CR_CGROUP_H__ */
