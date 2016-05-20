#ifndef __CR_PSTREE_H__
#define __CR_PSTREE_H__

#include "list.h"
#include "pid.h"
#include "images/core.pb-c.h"

/*
 * That's the init process which usually inherit
 * all orphaned children in the system.
 */
#define INIT_PID	(1)
struct pstree_item {
	struct pstree_item	*parent;
	struct list_head	children;	/* list of my children */
	struct list_head	sibling;	/* linkage in my parent's children list */

	struct pid		pid;
	pid_t			pgid;
	pid_t			sid;
	pid_t			born_sid;

	int			nr_threads;	/* number of threads */
	struct pid		*threads;	/* array of threads */
	CoreEntry		**core;
	TaskKobjIdsEntry	*ids;
};

struct rst_info;
/* See alloc_pstree_item() for details */
static inline struct rst_info *rsti(struct pstree_item *i)
{
	return (struct rst_info *)(i + 1);
}

struct ns_id;
struct dmp_info {
	struct ns_id *netns;
	/*
	 * We keep the creds here so that we can compare creds while seizing
	 * threads. Dumping tasks with different creds is not supported.
	 */
	struct proc_status_creds *pi_creds;
};

static inline struct dmp_info *dmpi(struct pstree_item *i)
{
	return (struct dmp_info *)(i + 1);
}

/* ids is alocated and initialized for all alive tasks */
static inline int shared_fdtable(struct pstree_item *item)
{
	return (item->parent &&
		item->ids->files_id == item->parent->ids->files_id);
}

static inline bool task_alive(struct pstree_item *i)
{
	return (i->pid.state == TASK_ALIVE) || (i->pid.state == TASK_STOPPED);
}

extern void free_pstree(struct pstree_item *root_item);
extern struct pstree_item *__alloc_pstree_item(bool rst);
#define alloc_pstree_item() __alloc_pstree_item(false)
extern void init_pstree_helper(struct pstree_item *ret);

extern struct pstree_item *lookup_create_item(pid_t pid);
extern void pstree_insert_pid(pid_t pid, struct pid *pid_node);
extern struct pid *pstree_pid_by_virt(pid_t pid);

extern struct pstree_item *root_item;
extern struct pstree_item *pstree_item_next(struct pstree_item *item);
#define for_each_pstree_item(pi) \
	for (pi = root_item; pi != NULL; pi = pstree_item_next(pi))

extern bool restore_before_setsid(struct pstree_item *child);
extern int prepare_pstree(void);

extern int dump_pstree(struct pstree_item *root_item);

struct pstree_item *pstree_item_by_real(pid_t virt);
struct pstree_item *pstree_item_by_virt(pid_t virt);

extern int pid_to_virt(pid_t pid);

struct task_entries;
extern struct task_entries *task_entries;

extern int get_task_ids(struct pstree_item *);
extern struct _TaskKobjIdsEntry *root_ids;

extern void core_entry_free(CoreEntry *core);
extern CoreEntry *core_entry_alloc(int alloc_thread_info, int alloc_tc);
extern int pstree_alloc_cores(struct pstree_item *item);
extern void pstree_free_cores(struct pstree_item *item);

extern int collect_pstree_ids(void);

extern int preorder_pstree_traversal(struct pstree_item *item, int (*f)(struct pstree_item *));
#endif /* __CR_PSTREE_H__ */
