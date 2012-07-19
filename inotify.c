#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <utime.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <aio.h>

#include "compiler.h"
#include "types.h"
#include "inotify.h"
#include "proc_parse.h"
#include "syscall.h"
#include "crtools.h"
#include "mount.h"
#include "image.h"
#include "util.h"
#include "files.h"
#include "file-ids.h"
#include "log.h"
#include "list.h"
#include "lock.h"

#include "protobuf.h"
#include "protobuf/inotify.pb-c.h"

struct inotify_wd_info {
	struct list_head		list;
	InotifyWdEntry			*iwe;
};

struct inotify_file_info {
	struct list_head		list;
	InotifyFileEntry		*ife;
	struct list_head		marks;
	struct file_desc		d;
};

static LIST_HEAD(info_head);

/* Checks if file desciptor @lfd is inotify */
int is_inotify_link(int lfd)
{
	return is_anon_link_type(lfd, "inotify");
}

void show_inotify_wd(int fd_inotify_wd, struct cr_options *o)
{
	pb_show_plain(fd_inotify_wd, inotify_wd_entry);
}

void show_inotify(int fd_inotify, struct cr_options *o)
{
	pb_show_plain(fd_inotify, inotify_file_entry);
}

static int dump_inotify_entry(union fdinfo_entries *e, void *arg)
{
	InotifyWdEntry *we = &e->ify;

	we->id = *(u32 *)arg;
	pr_info("inotify wd: wd 0x%08x s_dev 0x%08x i_ino 0x%16lx mask 0x%08x\n",
			we->wd, we->s_dev, we->i_ino, we->mask);
	pr_info("\t[fhandle] bytes 0x%08x type 0x%08x __handle 0x%016lx:0x%016lx\n",
			we->f_handle->bytes, we->f_handle->type,
			we->f_handle->handle[0], we->f_handle->handle[1]);
	return pb_write(fdset_fd(glob_fdset, CR_FD_INOTIFY_WD), we, inotify_wd_entry);
}

static int dump_one_inotify(int lfd, u32 id, const struct fd_parms *p)
{
	InotifyFileEntry ie = INOTIFY_FILE_ENTRY__INIT;

	ie.id = id;
	ie.flags = p->flags;
	ie.fown = (FownEntry *)&p->fown;

	pr_info("inotify: id 0x%08x flags 0x%08x\n", ie.id, ie.flags);
	if (pb_write(fdset_fd(glob_fdset, CR_FD_INOTIFY), &ie, inotify_file_entry))
		return -1;

	return parse_fdinfo(lfd, FD_TYPES__INOTIFY, dump_inotify_entry, &id);
}

static const struct fdtype_ops inotify_ops = {
	.type		= FD_TYPES__INOTIFY,
	.make_gen_id	= make_gen_id,
	.dump		= dump_one_inotify,
};

int dump_inotify(struct fd_parms *p, int lfd, const struct cr_fdset *set)
{
	return do_dump_gen_file(p, lfd, &inotify_ops, set);
}

static int restore_one_inotify(int inotify_fd, InotifyWdEntry *iwe)
{
	char path[32];
	int mntfd, ret = -1;
	int wd, target;
	fh_t handle = { };

	/* syscall waits for strict structure here */
	handle.type	= iwe->f_handle->type;
	handle.bytes	= iwe->f_handle->bytes;

	memcpy(handle.__handle, iwe->f_handle->handle,
	       min(pb_repeated_size(iwe->f_handle, handle),
		   sizeof(handle.__handle)));

	mntfd = open_mount(iwe->s_dev);
	if (mntfd < 0) {
		pr_err("Mount root for 0x%08x not found\n", iwe->s_dev);
		return -1;
	}

	target = sys_open_by_handle_at(mntfd, (void *)&handle, 0);
	if (target < 0) {
		pr_perror("Can't open file handle for 0x%08x:0x%016lx",
			  iwe->s_dev, iwe->i_ino);
		return -1;
	}

	snprintf(path, sizeof(path), "/proc/self/fd/%d", target);
	pr_debug("\t\tRestore watch for 0x%08x:0x%016lx\n", iwe->s_dev, iwe->i_ino);

	/*
	 * FIXME The kernel allocates wd-s sequentially,
	 * this is suboptimal, but the kernel doesn't
	 * provide and API for this yet :(
	 */
	wd = 1;
	while (wd >= 0) {
		wd = inotify_add_watch(inotify_fd, path, iwe->mask);
		if (wd < 0) {
			pr_err("Can't add watch for %d with %d\n", inotify_fd, iwe->wd);
			break;
		} else if (wd == iwe->wd) {
			ret = 0;
			break;
		} else if (wd > iwe->wd) {
			pr_err("Usorted watch found for %d with %d\n", inotify_fd, iwe->wd);
			break;
		}

		pr_debug("\t\tWatch got %d but %d expected\n", wd, iwe->wd);
		inotify_rm_watch(inotify_fd, wd);
	}

	close(mntfd);
	close(target);

	return ret;
}

static int open_inotify_fd(struct file_desc *d)
{
	struct inotify_file_info *info;
	struct inotify_wd_info *wd_info;
	int tmp;

	info = container_of(d, struct inotify_file_info, d);

	tmp = inotify_init1(info->ife->flags);
	if (tmp < 0) {
		pr_perror("Can't create inotify for 0x%08x", info->ife->id);
		return -1;
	}

	list_for_each_entry(wd_info, &info->marks, list) {
		pr_info("\tRestore inotify for 0x%08x\n", wd_info->iwe->id);
		if (restore_one_inotify(tmp, wd_info->iwe)) {
			close_safe(&tmp);
			break;
		}
	}

	if (restore_fown(tmp, info->ife->fown))
		close_safe(&tmp);

	return tmp;
}

static struct file_desc_ops desc_ops = {
	.type = FD_TYPES__INOTIFY,
	.open = open_inotify_fd,
};

static int collect_mark(struct inotify_wd_info *mark)
{
	struct inotify_file_info *p;

	list_for_each_entry(p, &info_head, list) {
		if (p->ife->id == mark->iwe->id) {
			list_add(&mark->list, &p->marks);
			return 0;
		}
	}

	return -1;
}

int collect_inotify(void)
{
	struct inotify_file_info *info;
	struct inotify_wd_info *mark;
	int image_fd = -1, image_wd = -1, ret = -1;

	image_fd = open_image_ro(CR_FD_INOTIFY);
	if (image_fd < 0)
		return -1;

	while (1) {
		info = xmalloc(sizeof(*info));
		if (!info)
			return -1;

		ret = pb_read_eof(image_fd, &info->ife, inotify_file_entry);
		if (ret < 0)
			goto err;
		else if (!ret)
			break;

		INIT_LIST_HEAD(&info->list);
		INIT_LIST_HEAD(&info->marks);

		list_add(&info->list, &info_head);
	}

	ret = -1;

	image_wd = open_image_ro(CR_FD_INOTIFY_WD);
	if (image_wd < 0)
		goto err;

	while (1) {
		ret = -1;
		mark = xmalloc(sizeof(*mark));
		if (!mark)
			goto err;

		ret = pb_read_eof(image_wd, &mark->iwe, inotify_wd_entry);
		if (ret < 0)
			goto err;
		else if (!ret)
			break;

		if (collect_mark(mark)) {
			ret = -1;
			pr_err("Can't find inotify with id 0x%08x\n", mark->iwe->id);
			goto err;
		}
	}

	list_for_each_entry(info, &info_head, list) {
		pr_info("Collected inotify: id 0x%08x flags 0x%08x\n", info->ife->id, info->ife->flags);
		file_desc_add(&info->d, info->ife->id, &desc_ops);
	}
	ret = 0;
err:
	close_safe(&image_wd);
	close_safe(&image_fd);

	return ret;
}
