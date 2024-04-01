#ifndef __CR_TIMER_H__
#define __CR_TIMER_H__

#include "images/core.pb-c.h"

struct task_restore_args;
struct pstree_item;
struct parasite_ctl;
struct proc_posix_timers_stat;

extern int prepare_itimers(int pid, struct task_restore_args *args, CoreEntry *core);
extern int prepare_posix_timers(int pid, struct task_restore_args *ta, CoreEntry *core);

extern int parasite_dump_itimers_seized(struct parasite_ctl *ctl, struct pstree_item *item);
extern int parasite_dump_posix_timers_seized(struct proc_posix_timers_stat *proc_args, struct parasite_ctl *ctl,
					     struct pstree_item *item);
#endif
