#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mount.h>

#include <errno.h>

#include "compiler.h"
#include "asm/string.h"
#include "asm/types.h"
#include "syscall.h"
#include "log.h"
#include "util-pie.h"

int open_detach_mount(char *dir)
{
	int fd, ret;

	fd = sys_open(dir, O_RDONLY | O_DIRECTORY, 0);
	if (fd < 0)
		pr_err("Can't open directory %s: %d\n", dir, fd);

	ret = sys_umount2(dir, MNT_DETACH);
	if (ret) {
		pr_perror("Can't detach mount %s: %d\n", dir, ret);
		goto err_close;
	}

	ret = sys_rmdir(dir);
	if (ret) {
		pr_perror("Can't remove tmp dir %s: %d\n", dir, ret);
		goto err_close;
	}

	return fd;

err_close:
	if (fd >= 0)
		sys_close(fd);
	return -1;
}
