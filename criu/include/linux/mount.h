#ifndef _CRIU_LINUX_MOUNT_H
#define _CRIU_LINUX_MOUNT_H

#include "common/config.h"
#include "compel/plugins/std/syscall-codes.h"

#ifdef CONFIG_HAS_FSCONFIG
#include <linux/mount.h>
#else
enum fsconfig_command {
	FSCONFIG_SET_FLAG = 0, /* Set parameter, supplying no value */
	FSCONFIG_SET_STRING = 1, /* Set parameter, supplying a string value */
	FSCONFIG_SET_BINARY = 2, /* Set parameter, supplying a binary blob value */
	FSCONFIG_SET_PATH = 3, /* Set parameter, supplying an object by path */
	FSCONFIG_SET_PATH_EMPTY = 4, /* Set parameter, supplying an object by (empty) path */
	FSCONFIG_SET_FD = 5, /* Set parameter, supplying an object by fd */
	FSCONFIG_CMD_CREATE = 6, /* Invoke superblock creation */
	FSCONFIG_CMD_RECONFIGURE = 7, /* Invoke superblock reconfiguration */
};
#endif

static inline int sys_fsopen(const char *fsname, unsigned int flags)
{
	return syscall(__NR_fsopen, fsname, flags);
}
static inline int sys_fsconfig(int fd, unsigned int cmd, const char *key, const char *value, int aux)
{
	return syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}
static inline int sys_fsmount(int fd, unsigned int flags, unsigned int attr_flags)
{
	return syscall(__NR_fsmount, fd, flags, attr_flags);
}

#endif
