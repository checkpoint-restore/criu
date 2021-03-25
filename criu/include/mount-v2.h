#ifndef __CR_MOUNT_V2_H__
#define __CR_MOUNT_V2_H__

#include "linux/mount.h"

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

#endif /* __CR_MOUNT_V2_H__ */
