#ifndef __CR_PSTREE_H__
#define __CR_PSTREE_H__

#include "list.h"
#include "pid.h"
#include "image.h"
#include "rst_info.h"
#include "protobuf/core.pb-c.h"

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

	int			state;		/* TASK_XXX constants */

	int			nr_threads;	/* number of threads */
	struct pid		*threads;	/* array of threads */
	CoreEntry		**core;
	TaskKobjIdsEntry	*ids;
};

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
	return (i->state == TASK_ALIVE) || (i->state == TASK_STOPPED);
}

extern void free_pstree(struct pstree_item *root_item);
extern struct pstree_item *__alloc_pstree_item(bool rst);
#define alloc_pstree_item() __alloc_pstree_item(false)
#define alloc_pstree_item_with_rst() __alloc_pstree_item(true)
extern struct pstree_item *alloc_pstree_helper(void);

extern struct pstree_item *root_item;
extern struct pstree_item *pstree_item_next(struct pstree_item *item);
#define for_each_pstree_item(pi) \
	for (pi = root_item; pi != NULL; pi = pstree_item_next(pi))

extern bool restore_before_setsid(struct pstree_item *child);
extern int prepare_pstree(void);

extern int dump_pstree(struct pstree_item *root_item);
extern bool pid_in_pstree(pid_t pid);

struct task_entries;
extern struct task_entries *task_entries;

extern int get_task_ids(struct pstree_item *);
extern struct _TaskKobjIdsEntry *root_ids;

extern void core_entry_free(CoreEntry *core);
extern CoreEntry *core_entry_alloc(int alloc_thread_info, int alloc_tc);
extern int pstree_alloc_cores(struct pstree_item *item);
extern void pstree_free_cores(struct pstree_item *item);

extern int collect_pstree_ids(void);

#endif /* __CR_PSTREE_H__ */
