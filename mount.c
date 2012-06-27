#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>

#include "types.h"
#include "util.h"
#include "log.h"
#include "mount.h"
#include "proc_parse.h"

static struct mount_info *mntinfo;

int open_mount(unsigned int s_dev)
{
	struct mount_info *i;

	for (i = mntinfo; i != NULL; i = i->next)
		if (s_dev == i->s_dev)
			return open(i->mountpoint, O_RDONLY);

	return -ENOENT;
}

int collect_mount_info(void)
{
	mntinfo = parse_mountinfo(getpid());
	if (!mntinfo) {
		pr_err("Parsing mountinfo %d failed\n", getpid());
		return -1;
	}

	return 0;
}

int dump_mnt_ns(int ns_pid, struct cr_fdset *fdset)
{
	return -1;
}

void show_mountpoints(int fd, struct cr_options *o)
{
	pr_img_head(CR_FD_MOUNTPOINTS);
	pr_img_tail(CR_FD_MOUNTPOINTS);
}
