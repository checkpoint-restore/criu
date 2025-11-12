#ifndef __CR_MOUNT_V2_H__
#define __CR_MOUNT_V2_H__

#include "linux/mount.h"
#include "linux/openat2.h"

#include "common/list.h"

#include <compel/plugins/std/syscall-codes.h>

#ifndef MOVE_MOUNT_SET_GROUP
#define MOVE_MOUNT_SET_GROUP 0x00000100 /* Set sharing group instead */
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004 /* Empty from path permitted */
#endif
#ifndef MOVE_MOUNT_T_EMPTY_PATH
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040 /* Empty to path permitted */
#endif

static inline int sys_move_mount(int from_dirfd, const char *from_pathname, int to_dirfd, const char *to_pathname,
				 unsigned int flags)
{
	return syscall(__NR_move_mount, from_dirfd, from_pathname, to_dirfd, to_pathname, flags);
}

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1 /* Clone the target tree and attach the clone */
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC /* Close the file on execve() */
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100 /* Do not follow symbolic links. */
#endif
#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0x800 /* Suppress terminal automount traversal */
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000 /* Allow empty relative pathname */
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000 /* Apply to the entire subtree */
#endif

static inline int sys_open_tree(int dfd, const char *filename, unsigned int flags)
{
	return syscall(__NR_open_tree, dfd, filename, flags);
}

#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV 0x01 /* Block mount-point crossings (includes bind-mounts). */
#endif

#ifndef STATMOUNT_SB_BASIC
#define STATMOUNT_SB_BASIC		0x00000001U     /* Want/got sb_... */
#endif

#ifndef STATMOUNT_MNT_BASIC
#define STATMOUNT_MNT_BASIC		0x00000002U	/* Want/got mnt_... */
#endif

#ifndef STATMOUNT_PROPAGATE_FROM
#define STATMOUNT_PROPAGATE_FROM	0x00000004U	/* Want/got propagate_from */
#endif

#ifndef STATMOUNT_MNT_ROOT
#define STATMOUNT_MNT_ROOT		0x00000008U	/* Want/got mnt_root  */
#endif

#ifndef STATMOUNT_MNT_POINT
#define STATMOUNT_MNT_POINT		0x00000010U	/* Want/got mnt_point */
#endif

#ifndef STATMOUNT_FS_TYPE
#define STATMOUNT_FS_TYPE		0x00000020U	/* Want/got fs_type */
#endif

#ifndef STATMOUNT_MNT_NS_ID
#define STATMOUNT_MNT_NS_ID		0x00000040U	/* Want/got mnt_ns_id */
#endif

#ifndef STATMOUNT_MNT_OPTS
#define STATMOUNT_MNT_OPTS		0x00000080U	/* Want/got mnt_opts */
#endif

#ifndef STATMOUNT_FS_SUBTYPE
#define STATMOUNT_FS_SUBTYPE		0x00000100U	/* Want/got fs_subtype */
#endif

#ifndef STATMOUNT_SB_SOURCE
#define STATMOUNT_SB_SOURCE		0x00000200U	/* Want/got sb_source */
#endif

#ifndef STATMOUNT_OPT_ARRAY
#define STATMOUNT_OPT_ARRAY		0x00000400U	/* Want/got opt_... */
#endif

#ifndef STATMOUNT_OPT_SEC_ARRAY
#define STATMOUNT_OPT_SEC_ARRAY		0x00000800U	/* Want/got opt_sec... */
#endif

#ifndef STATMOUNT_SUPPORTED_MASK
#define STATMOUNT_SUPPORTED_MASK	0x00001000U	/* Want/got supported mask flags */
#endif

#ifndef STATMOUNT_MNT_UIDMAP
#define STATMOUNT_MNT_UIDMAP		0x00002000U	/* Want/got uidmap... */
#endif

#ifndef STATMOUNT_MNT_GIDMAP
#define STATMOUNT_MNT_GIDMAP		0x00004000U	/* Want/got gidmap... */
#endif

#ifndef STATMOUNT_BY_FD
#define STATMOUNT_BY_FD		0x0000001U /* want mountinfo for given fd */
#endif

#ifndef MNT_ID_REQ_SIZE_VER1
#define MNT_ID_REQ_SIZE_VER1	32 /* sizeof second published struct */
#endif

struct mnt_id_req {
	__u32 size;
	__u32 fd;
	__u64 mnt_id;
	__u64 param;
	__u64 mnt_ns_id;
};

struct statmount {
	__u32 size;		/* Total size, including strings */
	__u32 mnt_opts;		/* [str] Options (comma separated, escaped) */
	__u64 mask;		/* What results were written */
	__u32 sb_dev_major;	/* Device ID */
	__u32 sb_dev_minor;
	__u64 sb_magic;		/* ..._SUPER_MAGIC */
	__u32 sb_flags;		/* SB_{RDONLY,SYNCHRONOUS,DIRSYNC,LAZYTIME} */
	__u32 fs_type;		/* [str] Filesystem type */
	__u64 mnt_id;		/* Unique ID of mount */
	__u64 mnt_parent_id;	/* Unique ID of parent (for root == mnt_id) */
	__u32 mnt_id_old;	/* Reused IDs used in proc/.../mountinfo */
	__u32 mnt_parent_id_old;
	__u64 mnt_attr;		/* MOUNT_ATTR_... */
	__u64 mnt_propagation;	/* MS_{SHARED,SLAVE,PRIVATE,UNBINDABLE} */
	__u64 mnt_peer_group;	/* ID of shared peer group */
	__u64 mnt_master;	/* Mount receives propagation from this ID */
	__u64 propagate_from;	/* Propagation from in current namespace */
	__u32 mnt_root;		/* [str] Root of mount relative to root of fs */
	__u32 mnt_point;	/* [str] Mountpoint relative to current root */
	__u64 mnt_ns_id;	/* ID of the mount namespace */
	__u32 fs_subtype;	/* [str] Subtype of fs_type (if any) */
	__u32 sb_source;	/* [str] Source string of the mount */
	__u32 opt_num;		/* Number of fs options */
	__u32 opt_array;	/* [str] Array of nul terminated fs options */
	__u32 opt_sec_num;	/* Number of security options */
	__u32 opt_sec_array;	/* [str] Array of nul terminated security options */
	__u64 supported_mask;	/* Mask flags that this kernel supports */
	__u32 mnt_uidmap_num;	/* Number of uid mappings */
	__u32 mnt_uidmap;	/* [str] Array of uid mappings (as seen from callers namespace) */
	__u32 mnt_gidmap_num;	/* Number of gid mappings */
	__u32 mnt_gidmap;	/* [str] Array of gid mappings (as seen from callers namespace) */
	__u64 __spare2[43];
	char str[];		/* Variable size part containing strings */
};

static inline long sys_openat2(int dirfd, const char *pathname, struct open_how *how, size_t size)
{
	return syscall(__NR_openat2, dirfd, pathname, how, size);
}

extern int check_mount_v2(void);

struct sharing_group {
	/* This pair identifies the group */
	int shared_id;
	int master_id;

	/* List of shared groups */
	struct list_head list;

	/* List of mounts in this group */
	struct list_head mnt_list;

	/*
	 * List of dependent shared groups:
	 * - all siblings have equal master_id
	 * - the parent has shared_id equal to children's master_id
	 *
	 * This is a bit tricky: parent pointer indicates if there is one
	 * parent sharing_group in list or only siblings.
	 * So for traversal if parent pointer is set we can do:
	 *   list_for_each_entry(t, &sg->parent->children, siblings)
	 * and otherwise we can do:
	 *   list_for_each_entry(t, &sg->siblings, siblings)
	 */
	struct list_head children;
	struct list_head siblings;
	struct sharing_group *parent;

	char *source;
};

extern int resolve_shared_mounts_v2(void);
extern int prepare_mnt_ns_v2(void);

#endif /* __CR_MOUNT_V2_H__ */
