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

static struct proc_mountinfo *mntinfo;
static int nr_mntinfo;

int open_mount(unsigned int s_dev)
{
	static int last = 0;
	int i;

again:
	for (i = last; i < nr_mntinfo; i++) {
		if (s_dev == mntinfo[i].s_dev) {
			last = i;
			return open(mntinfo[i].mountpoint, O_RDONLY);
		}
	}

	if (last) {
		last = 0;
		goto again;
	}

	return -ENOENT;
}

int collect_mount_info(void)
{
	nr_mntinfo = 64;
	mntinfo = xmalloc(sizeof(*mntinfo) * nr_mntinfo);
	if (!mntinfo)
		return -1;

	nr_mntinfo = parse_mountinfo(getpid(), mntinfo, nr_mntinfo);
	if (nr_mntinfo < 1) {
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
