#ifndef __CR_CGROUP_H__
#define __CR_CGROUP_H__
#include "asm/int.h"
struct pstree_item;
extern u32 root_cg_set;
int dump_task_cgroup(struct pstree_item *, u32 *);
int dump_cgroups(void);
int prepare_task_cgroup(struct pstree_item *);
int prepare_cgroup(void);
/* Restore things like cpu_limit in known cgroups. */
int prepare_cgroup_properties(void);
void fini_cgroup(void);

struct cg_controller;

struct cgroup_prop {
	char			*name;
	char			*value;
	struct list_head	list;
};

/* This describes a particular cgroup path, e.g. the '/lxc/u1' part of
 * 'blkio/lxc/u1' and any properties it has.
 */
struct cgroup_dir {
	char			*path;

	struct list_head	properties;
	unsigned int		n_properties;

	/* this is how children are linked together */
	struct list_head	siblings;

	/* more cgroup_dirs */
	struct list_head	children;
	unsigned int		n_children;
};

/* This describes a particular cgroup controller, e.g. blkio or cpuset.
 * The heads are subdirectories organized in their tree format.
 */
struct cg_controller {
	unsigned int		n_controllers;
	char			**controllers;

	/* cgroup_dirs */
	struct list_head 	heads;
	unsigned int		n_heads;

	/* for cgroup list in cgroup.c */
	struct list_head	l;
};
struct cg_controller *new_controller(const char *name);

/* parse all global cgroup information into structures */
int parse_cg_info(void);
int new_cg_root_add(char *controller, char *newroot);
#endif /* __CR_CGROUP_H__ */
