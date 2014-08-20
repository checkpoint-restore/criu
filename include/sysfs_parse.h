#ifndef __CR_SYSFS_PARSE_H__
#define __CR_SYSFS_PARSE_H__

#define SYSFS_AUFS	"/sys/fs/aufs/"
#define SBINFO_LEN	(3 + 16 + 1)			/* si_%lx */
#define SBINFO_PATH_LEN	(sizeof SYSFS_AUFS + SBINFO_LEN) /* /sys/fs/aufs/<sbinfo> */
#define AUFSBR_PATH_LEN	(SBINFO_PATH_LEN + 6 + 1)	/* /sys/fs/aufs/<sbinfo>/br%3d */

extern int parse_aufs_branches(struct mount_info *mi);
extern int fixup_aufs_vma_fd(struct vma_area *vma);
extern void free_aufs_branches(void);

#endif /* __CR_SYSFS_PARSE_H__ */

