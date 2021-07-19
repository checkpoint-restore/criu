#ifndef __CR_CGROUP_H__
#define __CR_CGROUP_H__

#include "int.h"
#include "images/core.pb-c.h"

struct pstree_item;
struct parasite_dump_cgroup_args;
extern u32 root_cg_set;
int dump_task_cgroup(struct pstree_item *, u32 *, struct parasite_dump_cgroup_args *args);
int dump_cgroups(void);
int prepare_task_cgroup(struct pstree_item *);
int prepare_cgroup(void);
/* Restore things like cpu_limit in known cgroups. */
int prepare_cgroup_properties(void);
int restore_freezer_state(void);
void fini_cgroup(void);

struct cg_controller;

struct cgroup_prop {
	char *name;
	char *value;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	struct list_head list;
};

/* This describes a particular cgroup path, e.g. the '/lxc/u1' part of
 * 'blkio/lxc/u1' and any properties it has.
 */
struct cgroup_dir {
	char *path;
	mode_t mode;
	uid_t uid;
	gid_t gid;

	struct list_head properties;
	unsigned int n_properties;

	/* this is how children are linked together */
	struct list_head siblings;

	/* more cgroup_dirs */
	struct list_head children;
	unsigned int n_children;
};

/* This describes a particular cgroup controller, e.g. blkio or cpuset.
 * The heads are subdirectories organized in their tree format.
 */
struct cg_controller {
	unsigned int n_controllers;
	char **controllers;

	/* cgroup_dirs */
	struct list_head heads;
	unsigned int n_heads;

	/* for cgroup list in cgroup.c */
	struct list_head l;
};
struct cg_controller *new_controller(const char *name);

/* parse all global cgroup information into structures */
int parse_cg_info(void);
int new_cg_root_add(char *controller, char *newroot);

extern struct ns_desc cgroup_ns_desc;

/*
 * This struct describes a group controlled by one controller.
 * The @name is the controller name or 'name=...' for named cgroups.
 * The @path is the path from the hierarchy root.
 */

struct cg_ctl {
	struct list_head l;
	char *name;
	char *path;
	u32 cgns_prefix;
};

/*
 * Returns the list of cg_ctl-s sorted by name
 */
struct list_head;
struct parasite_dump_cgroup_args;
extern int parse_task_cgroup(int pid, struct parasite_dump_cgroup_args *args, struct list_head *l, unsigned int *n);
extern void put_ctls(struct list_head *);

int collect_controllers(struct list_head *cgroups, unsigned int *n_cgroups);

#endif /* __CR_CGROUP_H__ */
