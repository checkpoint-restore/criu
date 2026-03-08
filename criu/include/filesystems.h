#ifndef __CR_FILESYSTEMS_H__
#define __CR_FILESYSTEMS_H__

#include "images/userns.pb-c.h"

extern struct fstype *find_fstype_by_name(char *fst);
extern struct fstype *decode_fstype(u32 fst);
extern bool add_fsname_auto(const char *names);

struct mount_info;
typedef int (*mount_fn_t)(struct mount_info *mi, const char *src, const char *fstype, unsigned long mountflags);

int binfmt_misc_dump_sandboxed(pid_t pid, BinfmtMiscEntry ***pb_bmes);
int binfmt_misc_restore_sandboxed(pid_t pid, BinfmtMiscEntry **bmes, size_t n);
void free_pb_binfmt_misc_entries(BinfmtMiscEntry **bmes, int n);

struct fstype {
	char *name;
	int code;
	int (*dump)(struct mount_info *pm);
	int (*restore)(struct mount_info *pm);
	int (*check_bindmount)(struct mount_info *pm);
	int (*parse)(struct mount_info *pm);
	int (*collect)(struct mount_info *pm);
	bool (*sb_equal)(struct mount_info *a, struct mount_info *b);
	mount_fn_t mount;
};

extern struct fstype *fstype_auto(void);

/* callback for AUFS support */
extern int aufs_parse(struct mount_info *mi);

/* callback for OverlayFS support */
extern int overlayfs_parse(struct mount_info *mi);

#endif
