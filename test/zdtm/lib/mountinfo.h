#ifndef __ZDTM_MOUNTINFO__
#define __ZDTM_MOUNTINFO__

#include "list.h"

struct mountinfo_zdtm {
	int mnt_id;
	int parent_mnt_id;
	char *mountpoint;
	char *root;
	unsigned int s_dev;
	int shared_id;
	int master_id;
	char *fstype;

	/* list of all mounts */
	struct list_head list;
};

struct mntns_zdtm {
	struct list_head mountinfo_list;
	struct list_head topology_list;
	struct mountinfo_topology *tree;
	struct list_head sharing_groups_list;
};

#define MNTNS_ZDTM_INIT(name)                                                    \
	{                                                                        \
		.mountinfo_list = LIST_HEAD_INIT(name.mountinfo_list),           \
		.topology_list = LIST_HEAD_INIT(name.topology_list),             \
		.sharing_groups_list = LIST_HEAD_INIT(name.sharing_groups_list), \
	}
#define MNTNS_ZDTM(name) struct mntns_zdtm name = MNTNS_ZDTM_INIT(name)

struct sharing_group {
	int shared_id;
	int master_id;
	unsigned int s_dev;

	struct sharing_group *parent;
	struct list_head children;
	struct list_head siblings;

	int topology_id;

	struct list_head mounts_list;

	struct list_head list;
};

struct mountinfo_topology {
	struct mountinfo_zdtm *mountinfo;

	struct mountinfo_topology *parent;
	struct list_head children;
	struct list_head siblings;

	int topology_id;

	struct sharing_group *sharing;
	struct list_head sharing_list;

	struct list_head list;
};

extern int mntns_parse_mountinfo(struct mntns_zdtm *mntns);
extern void mntns_free_all(struct mntns_zdtm *mntns);
extern int mntns_compare(struct mntns_zdtm *mntns_a, struct mntns_zdtm *mntns_b);

#endif
