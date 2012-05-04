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
#include "mount.h"
#include "proc_parse.h"

/*
 * Returns path for mount device @s_dev
 *
 * FIXME this is not sufficient in general
 * since mount points can be overmounted but
 * works for now.
 */
int open_mnt_root(unsigned int s_dev, struct proc_mountinfo *mntinfo, int nr_mntinfo)
{
	static int last = 0;
	int i;

again:
	for (i = last; i < nr_mntinfo; i++) {
		if (s_dev == mntinfo[i].s_dev) {
			last = i;
			return open(mntinfo[i].mnt_root, O_RDONLY);
		}
	}

	if (last) {
		last = 0;
		goto again;
	}

	return -ENOENT;
}
