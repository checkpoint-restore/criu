#ifndef FILE_IDS_H__
#define FILE_IDS_H__

#include "compiler.h"
#include "types.h"
#include "rbtree.h"

#define FD_ID_INVALID		(-1UL)
#define FD_PID_INVALID		((int)-2UL)

#define MAKE_FD_GENID(dev, ino, pos) \
	(((u32)(dev) ^ (u32)(ino) ^ (u32)(pos)))

extern long fd_id_entry_collect(u64 genid, pid_t pid, int fd);

#endif /* FILE_IDS_H__ */
