#ifndef __CR_FILESYSTEMS_H__
#define __CR_FILESYSTEMS_H__
extern struct fstype *find_fstype_by_name(char *fst);
extern struct fstype *decode_fstype(u32 fst);
extern bool add_fsname_auto(const char *names);

struct mount_info;
typedef int (*mount_fn_t)(struct mount_info *mi, const char *src, const
			  char *fstype, unsigned long mountflags);

struct fstype {
	char *name;
	int code;
	int (*dump)(struct mount_info *pm);
	int (*restore)(struct mount_info *pm);
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

/* FIXME -- remove */
extern struct list_head binfmt_misc_list;
#endif
