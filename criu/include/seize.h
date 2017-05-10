#ifndef __CR_SEIZE_H__
#define __CR_SEIZE_H__

extern int collect_pstree(void);
extern void pstree_switch_state(struct pstree_item *root_item, int st);
extern const char *get_real_freezer_state(void);
extern bool alarm_timeouted(void);

extern char *task_comm_info(pid_t pid, char *comm, size_t size);
extern char *__task_comm_info(pid_t pid);

#endif
