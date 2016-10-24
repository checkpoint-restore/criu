#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include "int.h"
#include "types.h"
#include "common/compiler.h"
#include "fcntl.h"
#include "log.h"
#include "util-pie.h"

#ifdef CR_NOGLIBC
# include "syscall.h"
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
