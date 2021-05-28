#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/capability.h>

#include "int.h"
#include "types.h"
#include "common/compiler.h"
#include "fcntl.h"
#include "log.h"
#include "util-pie.h"

#ifdef CR_NOGLIBC
# include <compel/plugins/std/syscall.h>
# define __sys(foo)     sys_##foo
#else
# define __sys(foo)     foo
#endif

#ifdef CR_NOGLIBC
#define __pr_perror(fmt, ...) pr_err(fmt "\n", ##__VA_ARGS__)
#else
#define __pr_perror(fmt, ...) pr_perror(fmt, ##__VA_ARGS__)
#endif

int open_detach_mount(char *dir)
{
	int fd, ret;

	fd = __sys(open)(dir, O_RDONLY | O_DIRECTORY, 0);
	if (fd < 0)
		__pr_perror("Can't open directory %s: %d", dir, fd);

	ret = __sys(umount2)(dir, MNT_DETACH);
	if (ret) {
		__pr_perror("Can't detach mount %s: %d", dir, ret);
		goto err_close;
	}

	ret = __sys(rmdir)(dir);
	if (ret) {
		__pr_perror("Can't remove tmp dir %s: %d", dir, ret);
		goto err_close;
	}

	return fd;

err_close:
	if (fd >= 0)
		__sys(close)(fd);
	return -1;
}

#ifndef CAP_CHECKPOINT_RESTORE
#define CAP_CHECKPOINT_RESTORE 40
#endif

static inline bool has_capability(int cap, u32 *cap_eff)
{
	int mask = CAP_TO_MASK(cap);
	int index = CAP_TO_INDEX(cap);
	u32 effective;

	effective = cap_eff[index];

	if (!(mask & effective)) {
		pr_debug("Effective capability %d missing\n", cap);
		return false;
	}

	return true;
}

inline bool has_cap_checkpoint_restore(u32 *cap_eff)
{
	/*
	 * Everything guarded by CAP_CHECKPOINT_RESTORE is also
	 * guarded by CAP_SYS_ADMIN. Check for both capabilities.
	 */
	if (has_capability(CAP_CHECKPOINT_RESTORE, cap_eff) ||
			has_capability(CAP_SYS_ADMIN, cap_eff))
		return true;

	return false;
}

inline bool has_cap_net_admin(u32 *cap_eff)
{
	return has_capability(CAP_NET_ADMIN, cap_eff);
}

inline bool has_cap_sys_chroot(u32 *cap_eff)
{
	return has_capability(CAP_SYS_CHROOT, cap_eff);
}

inline bool has_cap_setuid(u32 *cap_eff)
{
	return has_capability(CAP_SETUID, cap_eff);
}

inline bool has_cap_sys_resource(u32 *cap_eff)
{
	return has_capability(CAP_SYS_RESOURCE, cap_eff);
}
