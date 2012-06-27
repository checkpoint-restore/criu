#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>

#include "crtools.h"
#include "types.h"
#include "util.h"
#include "log.h"
#include "mount.h"
#include "proc_parse.h"
#include "image.h"

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

static int dump_one_mountpoint(struct mount_info *pm, int fd)
{
	struct mnt_entry me;

	pr_info("\t%d: %x:%s @ %s\n", pm->mnt_id, pm->s_dev,
			pm->root, pm->mountpoint);

	me.mnt_id = pm->mnt_id;
	me.root_dev = pm->s_dev;
	me.root_dentry_len = strlen(pm->root);
	me.parent_mnt_id = pm->parent_mnt_id;
	me.mountpoint_path_len = strlen(pm->mountpoint);

	me.flags = pm->flags;
	me.source_len = strlen(pm->source);
	me.options_len = strlen(pm->options);

	if (write_img(fd, &me))
		return -1;
	if (write_img_buf(fd, pm->root, me.root_dentry_len))
		return -1;
	if (write_img_buf(fd, pm->mountpoint, me.mountpoint_path_len))
		return -1;
	if (write_img_buf(fd, pm->source, me.source_len))
		return -1;
	if (write_img_buf(fd, pm->options, me.options_len))
		return -1;

	return 0;
}

int dump_mnt_ns(int ns_pid, struct cr_fdset *fdset)
{
	struct mount_info *pm;
	int img_fd;

	pm = parse_mountinfo(ns_pid);
	if (!pm) {
		pr_err("Can't parse %d's mountinfo\n", ns_pid);
		return -1;
	}

	pr_info("Dumping mountpoints\n");

	img_fd = fdset_fd(fdset, CR_FD_MOUNTPOINTS);
	do {
		struct mount_info *n = pm->next;

		if (dump_one_mountpoint(pm, img_fd))
			return -1;

		xfree(pm);
		pm = n;
	} while (pm);

	return 0;
}

void show_mountpoints(int fd, struct cr_options *o)
{
	struct mnt_entry me;
	char buf[PATH_MAX];

	pr_img_head(CR_FD_MOUNTPOINTS);

	while (1) {
		int ret;

		ret = read_img_eof(fd, &me);
		if (ret <= 0)
			break;

		pr_msg("%d:%d ", me.mnt_id, me.parent_mnt_id);

		ret = read_img_buf(fd, buf, me.root_dentry_len);
		if (ret < 0)
			break;

		buf[me.root_dentry_len] = '\0';
		pr_msg("%d:%d %s ", kdev_major(me.root_dev),
				kdev_minor(me.root_dev), buf);

		ret = read_img_buf(fd, buf, me.mountpoint_path_len);
		if (ret < 0)
			break;

		buf[me.mountpoint_path_len] = '\0';
		pr_msg("@ %s ", buf);

		pr_msg("flags %08x ", me.flags);

		ret = read_img_buf(fd, buf, me.source_len);
		if (ret < 0)
			break;

		buf[me.source_len] = '\0';
		pr_msg("dev %s ", buf);

		ret = read_img_buf(fd, buf, me.options_len);
		if (ret < 0)
			break;

		buf[me.options_len] = '\0';
		pr_msg("options %s\n", buf);
	}

	pr_img_tail(CR_FD_MOUNTPOINTS);
}
