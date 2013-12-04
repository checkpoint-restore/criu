#ifndef __CR_BTRFS_H__
#define __CR_BTRFS_H__

#include <asm/types.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/ioctl.h>

#include "asm/int.h"
#include "compiler.h"
#include "rbtree.h"

struct mount_info;

#define BTRFS_IOCTL_MAGIC		0x94
#define BTRFS_VOL_NAME_MAX		255

struct btrfs_root_ref {
	u64 dirid;
	u64 sequence;
	u16 name_len;
} __packed;

#define BTRFS_ROOT_ITEM_KEY		132
#define BTRFS_ROOT_BACKREF_KEY		144
#define BTRFS_FS_TREE_OBJECTID		5ULL

#define BTRFS_FIRST_FREE_OBJECTID	256ULL
#define BTRFS_LAST_FREE_OBJECTID	-256ULL

#define BTRFS_INO_LOOKUP_PATH_MAX	4080
struct btrfs_ioctl_ino_lookup_args {
	u64				treeid;
	u64				objectid;
	char				name[BTRFS_INO_LOOKUP_PATH_MAX];
};

struct btrfs_ioctl_search_header {
	u64				transid;
	u64				objectid;
	u64				offset;
	u32				type;
	u32				len;
};

struct btrfs_ioctl_search_key {
	u64				tree_id;
	u64				min_objectid;
	u64				max_objectid;
	u64				min_offset;
	u64				max_offset;
	u64				min_transid;
	u64				max_transid;
	u32				min_type;
	u32				max_type;
	u32				nr_items;
	u32				unused;
	u64				unused1;
	u64				unused2;
	u64				unused3;
	u64				unused4;
};

#define BTRFS_SEARCH_ARGS_BUFSIZE (4096 - sizeof(struct btrfs_ioctl_search_key))

struct btrfs_ioctl_search_args {
	struct btrfs_ioctl_search_key	key;
	char				buf[BTRFS_SEARCH_ARGS_BUFSIZE];
};

#define BTRFS_IOC_TREE_SEARCH		\
	_IOWR(BTRFS_IOCTL_MAGIC, 17, struct btrfs_ioctl_search_args)

#define BTRFS_IOC_INO_LOOKUP		\
	_IOWR(BTRFS_IOCTL_MAGIC, 18, struct btrfs_ioctl_ino_lookup_args)

extern int btrfs_parse_mountinfo(struct mount_info *m);
extern bool is_btrfs_subvol(dev_t vol_id, dev_t dev_id);

#endif /* __CR_BTRFS_H__ */
