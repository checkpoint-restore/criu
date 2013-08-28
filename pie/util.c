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
	int fd;

	fd = sys_open(dir, O_RDONLY | O_DIRECTORY, 0);
	if (fd < 0)
		pr_perror("Can't open directory");

	if (sys_umount2(dir, MNT_DETACH)) {
		pr_perror("Can't detach mount");
		goto err_close;
	}

	if (sys_rmdir(dir)) {
		pr_perror("Can't remove tmp dir");
		goto err_close;
	}

	return fd;

err_close:
	if (fd >= 0)
		sys_close(fd);
	return -1;
}
