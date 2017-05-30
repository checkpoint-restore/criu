#ifndef __CR_PSTREE_H__
#define __CR_PSTREE_H__

#include "common/list.h"
#include "common/lock.h"
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

	struct pid		*pid;
	struct pid		*pgid;
	struct pid		*sid;
	pid_t			born_sid;

	int			nr_threads;	/* number of threads */
	struct pid		**threads;	/* array of threads */
	CoreEntry		**core;
	TaskKobjIdsEntry	*ids;
	union {
		futex_t		task_st;
		unsigned long	task_st_le_bits;
	};
	struct ns_id		*user_ns;
	struct ns_id		*pid_for_children_ns;
};

#define vpid(item)	(item->pid->ns[0].virt)
#define vsid(item)	(item->sid->ns[0].virt)
#define vpgid(item)	(item->pgid->ns[0].virt)
#define vtid(item, i)	(item->threads[i]->ns[0].virt)

#define PID_SIZE(level) (sizeof(struct pid) + (level-1) * sizeof(((struct pid *)NULL)->ns[0]))

enum {
	FDS_EVENT_BIT	= 0,
};
#define FDS_EVENT (1 << FDS_EVENT_BIT)

extern struct pstree_item *current;

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
	struct page_pipe *mem_pp;
	struct parasite_ctl *parasite_ctl;
};

static inline struct dmp_info *dmpi(const struct pstree_item *i)
{
	return (struct dmp_info *)(i + 1);
}

/* ids is alocated and initialized for all alive tasks */
static inline int shared_fdtable(struct pstree_item *item)
{
	return (item->parent &&
		item->ids->files_id == item->parent->ids->files_id);
}

static inline bool is_alive_state(int state)
{
	return (state == TASK_ALIVE) || (state == TASK_STOPPED);
}

static inline bool task_alive(struct pstree_item *i)
{
	return is_alive_state(i->pid->state);
}

extern int get_free_pids(struct ns_id *ns, pid_t *pids);
extern void free_pstree_item(struct pstree_item *item);
extern void free_pstree(struct pstree_item *root_item);
extern struct pstree_item *__alloc_pstree_item(bool rst, int level);
#define alloc_pstree_item() __alloc_pstree_item(false, 1)
extern int init_pstree_helper(struct pstree_item *ret);

extern struct pstree_item *lookup_create_item(pid_t *pid, int level, uint32_t ns_id);
extern void pstree_insert_pid(struct pid *pid_node, uint32_t ns_id);
extern struct pid *__pstree_pid_by_virt(struct ns_id *ns, pid_t pid);
static inline struct pid *pstree_pid_by_virt(pid_t pid)
{
	extern struct ns_id *top_pid_ns;
	return __pstree_pid_by_virt(top_pid_ns, pid);
}

extern struct pstree_item *root_item;
extern struct pstree_item *pstree_item_next(struct pstree_item *item);
#define for_each_pstree_item(pi) \
	for (pi = root_item; pi != NULL; pi = pstree_item_next(pi))

extern bool restore_before_setsid(struct pstree_item *child);
extern int prepare_pstree(void);
extern int prepare_dummy_pstree(void);

extern int dump_pstree(struct pstree_item *root_item);

struct pstree_item *pstree_item_by_real(pid_t virt);
extern struct pstree_item *__pstree_item_by_virt(struct ns_id *ns, pid_t virt);
static inline struct pstree_item *pstree_item_by_virt(pid_t virt)
{
	extern struct ns_id *top_pid_ns;
	return __pstree_item_by_virt(top_pid_ns, virt);
}

extern int pid_to_virt(pid_t pid);

struct task_entries;
extern struct task_entries *task_entries;
extern int prepare_task_entries(void);
extern int prepare_dummy_task_state(struct pstree_item *pi);

extern int get_task_ids(struct pstree_item *);
extern struct _TaskKobjIdsEntry *root_ids;

extern void core_entry_free(CoreEntry *core);
extern CoreEntry *core_entry_alloc(int alloc_thread_info, int alloc_tc);
extern int pstree_alloc_cores(struct pstree_item *item);
extern void pstree_free_cores(struct pstree_item *item);

extern int collect_pstree_ids(void);
extern int fixup_pid_for_children_ns(TaskKobjIdsEntry *ids);

extern int preorder_pstree_traversal(struct pstree_item *item, int (*f)(struct pstree_item *));
extern int __set_next_pid(pid_t pid);
#endif /* __CR_PSTREE_H__ */
