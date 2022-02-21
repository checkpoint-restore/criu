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
};

extern int mntns_parse_mountinfo(struct mntns_zdtm *mntns);
extern void mntns_free_all(struct mntns_zdtm *mntns);

#endif
