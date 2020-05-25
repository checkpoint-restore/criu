#ifndef __CR_MOUNT_V2_H__
#define __CR_MOUNT_V2_H__

#include "linux/mount.h"
#include "linux/openat2.h"

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

static inline long sys_openat2(int dirfd, const char *pathname, struct open_how *how, size_t size)
{
	return syscall(__NR_openat2, dirfd, pathname, how, size);
}

extern int check_mount_v2(void);

#endif /* __CR_MOUNT_V2_H__ */
