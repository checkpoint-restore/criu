#ifndef PSTREE_H__
#define PSTREE_H__
#include "list.h"
#include "crtools.h"

struct pstree_item {
	struct list_head	list;
	struct pid		pid;
	struct pstree_item	*parent;
	struct list_head	children;	/* array of children */
	pid_t			pgid;
	pid_t			sid;
	pid_t			born_sid;
	int			state;		/* TASK_XXX constants */
	int			nr_threads;	/* number of threads */
	struct pid		*threads;	/* array of threads */
	struct rst_info		rst[0];
};

extern void free_pstree(struct pstree_item *root_item);
extern struct pstree_item *__alloc_pstree_item(bool rst);
#define alloc_pstree_item() __alloc_pstree_item(false)
#define alloc_pstree_item_with_rst() __alloc_pstree_item(true)

extern struct pstree_item *root_item;
extern struct pstree_item *pstree_item_next(struct pstree_item *item);
#define for_each_pstree_item(pi) \
	for (pi = root_item; pi != NULL; pi = pstree_item_next(pi))

extern bool restore_before_setsid(struct pstree_item *child);
extern int prepare_pstree(void);
extern int prepare_pstree_ids(void);

extern int dump_pstree(struct pstree_item *root_item);

struct task_entries;
extern struct task_entries *task_entries;
#endif
