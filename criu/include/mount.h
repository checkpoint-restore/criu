#ifndef __CR_MOUNT_H__
#define __CR_MOUNT_H__

#include <sys/types.h>

#include "asm/types.h"
#include "list.h"

struct proc_mountinfo;
struct pstree_item;
struct fstype;
struct ns_id;

/*
 * Structure to keep external mount points resolving info.
 *
 * On dump the key is the mountpoint as seen from the mount
 * namespace, the val is some name that will be put into image
 * instead of the mount point's root path.
 *
 * On restore the key is the name from the image (the one
 * mentioned above) and the val is the path in criu's mount
 * namespace that will become the mount point's root, i.e. --
 * be bind mounted to the respective mountpoint.
 */
struct ext_mount {
	struct list_head	list;
	char			*key;
	char			*val;
};

#define MOUNT_INVALID_DEV	(0)

struct mount_info {
	int			mnt_id;
	int			parent_mnt_id;
	unsigned int		s_dev;
	unsigned int		s_dev_rt;
	char			*root;
	/*
	 * During dump mountpoint contains path with dot at the
	 * beginning. It allows to use openat, statat, etc without
	 * creating a temporary copy of the path.
	 *
	 * On restore mountpoint is prepended with so called ns
	 * root path -- it's a place in fs where the namespace
	 * mount tree is constructed. Check mnt_roots for details.
	 * The ns_mountpoint contains path w/o this prefix.
	 */
	char			*mountpoint;
	char			*ns_mountpoint;
	int			fd;
	unsigned		flags;
	unsigned		sb_flags;
	int			master_id;
	int			shared_id;
	struct fstype		*fstype;
	char			*source;
	char			*options;
	char			*fsname;
	union {
		bool		mounted;
		bool		dumped;
	};
	bool			need_plugin;
	bool			is_ns_root;
	bool			deleted;
	struct mount_info	*next;
	struct ns_id		*nsid;

	struct ext_mount	*external;
	bool			internal_sharing;

	/* tree linkage */
	struct mount_info	*parent;
	struct mount_info	*bind;
	struct list_head	children;
	struct list_head	siblings;

	struct list_head	mnt_bind;	/* circular list of derivatives of one real mount */
	struct list_head	mnt_share;	/* circular list of shared mounts */
	struct list_head	mnt_slave_list;	/* list of slave mounts */
	struct list_head	mnt_slave;	/* slave list entry */
	struct mount_info	*mnt_master;	/* slave is on master->mnt_slave_list */

	struct list_head	postpone;

	void			*private;	/* associated filesystem data */
};

extern struct mount_info *mntinfo;
extern struct ns_desc mnt_ns_desc;

extern struct mount_info *mnt_entry_alloc();
extern void mnt_entry_free(struct mount_info *mi);

extern int __mntns_get_root_fd(pid_t pid);
extern int mntns_get_root_fd(struct ns_id *ns);
extern int mntns_get_root_by_mnt_id(int mnt_id);
extern struct ns_id *lookup_nsid_by_mnt_id(int mnt_id);

extern int open_mount(unsigned int s_dev);
extern int __open_mountpoint(struct mount_info *pm, int mnt_fd);
extern struct fstype *find_fstype_by_name(char *fst);
extern bool add_fsname_auto(const char *names);

extern struct mount_info *collect_mntinfo(struct ns_id *ns, bool for_dump);
extern int prepare_mnt_ns(void);

extern int pivot_root(const char *new_root, const char *put_old);

extern struct mount_info *lookup_overlayfs(char *rpath, unsigned int s_dev,
					   unsigned int st_ino, unsigned int mnt_id);
extern struct mount_info *lookup_mnt_id(unsigned int id);
extern struct mount_info *lookup_mnt_sdev(unsigned int s_dev);

extern dev_t phys_stat_resolve_dev(struct ns_id *, dev_t st_dev, const char *path);
extern bool phys_stat_dev_match(dev_t st_dev, dev_t phys_dev,
				struct ns_id *, const char *path);

extern int restore_task_mnt_ns(struct pstree_item *current);
extern void fini_restore_mntns(void);
extern int depopulate_roots_yard(int mntns_root, bool clean_remaps);

extern int rst_get_mnt_root(int mnt_id, char *path, int plen);
extern int ext_mount_add(char *key, char *val);
extern int mntns_maybe_create_roots(void);
extern int read_mnt_ns_img(void);
extern void cleanup_mnt_ns(void);

struct mount_info;
typedef int (*mount_fn_t)(struct mount_info *mi, const char *src, const
			  char *fstype, unsigned long mountflags);

struct fstype {
	char *name;
	int code;
	int (*dump)(struct mount_info *pm);
	int (*restore)(struct mount_info *pm);
	int (*parse)(struct mount_info *pm);
	mount_fn_t mount;
};

extern bool add_skip_mount(const char *mountpoint);
struct ns_id;
extern struct mount_info *parse_mountinfo(pid_t pid, struct ns_id *nsid, bool for_dump);

/* callback for AUFS support */
extern int aufs_parse(struct mount_info *mi);

/* callback for OverlayFS support */
extern int overlayfs_parse(struct mount_info *mi);

extern int check_mnt_id(void);

#endif /* __CR_MOUNT_H__ */
