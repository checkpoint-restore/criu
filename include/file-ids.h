#ifndef FILE_IDS_H__
#define FILE_IDS_H__

#include "compiler.h"
#include "types.h"
#include "rbtree.h"

#define FD_ID_INVALID		(-1UL)
#define FD_PID_INVALID		((int)-2UL)

struct fd_id_entry {
	struct rb_node	node;

	struct rb_root	subtree_root;
	struct rb_node	subtree_node;

	union {
		struct {
			u32		genid;	/* generic id, may have duplicates */
			u32		subid;	/* subid is always unique */
		} key;
		u64			id;
	} u;

	pid_t		pid;
	int		fd;
} __aligned(sizeof(long));

#define MAKE_FD_GENID(dev, ino, pos) \
	(((u32)(dev) ^ (u32)(ino) ^ (u32)(pos)))

extern struct fd_id_entry *fd_id_entry_collect(u32 genid, pid_t pid, int fd);

#endif /* FILE_IDS_H__ */
