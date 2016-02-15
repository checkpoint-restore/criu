#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <unistd.h>
#include <errno.h>

#include "compiler.h"
#include "asm/string.h"
#include "asm/types.h"
#include "fcntl.h"
#include "log.h"
#include "util-pie.h"

#ifdef CR_NOGLIBC
# include "syscall.h"
# define __sys(foo)     sys_##foo
#else
# define __sys(foo)     foo
#endif

int open_detach_mount(char *dir)
{
	int fd, ret;

	fd = __sys(open)(dir, O_RDONLY | O_DIRECTORY, 0);
	if (fd < 0)
		pr_err("Can't open directory %s: %d\n", dir, fd);

	ret = __sys(umount2)(dir, MNT_DETACH);
	if (ret) {
		pr_err("Can't detach mount %s: %d\n", dir, ret);
		goto err_close;
	}

	ret = __sys(rmdir)(dir);
	if (ret) {
		pr_err("Can't remove tmp dir %s: %d\n", dir, ret);
		goto err_close;
	}

	return fd;

err_close:
	if (fd >= 0)
		__sys(close)(fd);
	return -1;
}
