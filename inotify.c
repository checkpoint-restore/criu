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

struct inotify_wd_info {
	struct list_head		list;
	struct inotify_wd_entry		iwe;
};

struct inotify_file_info {
	struct list_head		list;
	struct inotify_file_entry	ife;
	struct list_head		marks;
	struct file_desc		d;
};

static LIST_HEAD(info_head);
static char fdinfo_buf[PAGE_SIZE];

/* Checks if file desciptor @lfd is inotify */
int is_inotify_link(int lfd)
{
	return is_anon_link_type(lfd, "inotify");
}

void show_inotify_wd(int fd_inotify_wd, struct cr_options *o)
{
	struct inotify_wd_entry e;

	pr_img_head(CR_FD_INOTIFY_WD);
	while (1) {
		int ret;

		ret = read_img_eof(fd_inotify_wd, &e);
		if (ret <= 0)
			goto out;

		pr_msg("inotify-wd: id 0x%08x 0x%08x s_dev 0x%08x i_ino 0x%016lx mask 0x%08x "
		       "[fhandle] 0x%08x 0x%08x 0x%016lx:0x%016lx ...\n",
		       e.id, e.wd, e.s_dev, e.i_ino, e.mask,
		       e.f_handle.bytes, e.f_handle.type,
		       e.f_handle.__handle[0],
		       e.f_handle.__handle[1]);
	}
out:
	pr_img_tail(CR_FD_INOTIFY_WD);
}

void show_inotify(int fd_inotify, struct cr_options *o)
{
	struct inotify_file_entry e;

	pr_img_head(CR_FD_INOTIFY);
	while (1) {
		int ret;

		ret = read_img_eof(fd_inotify, &e);
		if (ret <= 0)
			goto out;

		pr_msg("inotify: id 0x%08x flags 0x%08x\n\t", e.id, e.flags);
		show_fown_cont(&e.fown);
		pr_msg("\n");
	}
out:
	pr_img_tail(CR_FD_INOTIFY);
}

static char nybble(const char n)
{
       if      (n >= '0' && n <= '9') return n - '0';
       else if (n >= 'A' && n <= 'F') return n - ('A' - 10);
       else if (n >= 'a' && n <= 'f') return n - ('a' - 10);
       return 0;
}

static void parse_fhandle_encoded(char *tok, fh_t *f)
{
	char *d = (char *)f->__handle;
	int i = 0;

	memzero(d, sizeof(f->__handle));

	while (*tok == ' ')
		tok++;

	while (*tok) {
		if (i >= sizeof(f->__handle))
			break;
		d[i++] = (nybble(tok[0]) << 4) | nybble(tok[1]);
		if (tok[1])
			tok += 2;
		else
			break;
	}
}

int dump_one_inotify(int lfd, u32 id, const struct fd_parms *p)
{
	struct inotify_file_entry ie;
	struct inotify_wd_entry we;
	int image_fd, image_wd;
	int ret = -1, fdinfo;
	char *tok, *pos;

	image_fd = fdset_fd(glob_fdset, CR_FD_INOTIFY);
	image_wd = fdset_fd(glob_fdset, CR_FD_INOTIFY_WD);

	pr_info("Dumping inotify %d with id 0x%08x\n", lfd, id);

	ie.id	= id;
	ie.flags= p->flags;
	ie.fown	= p->fown;

	we.id	= id;

	snprintf(fdinfo_buf, sizeof(fdinfo_buf), "/proc/self/fdinfo/%d", lfd);
	fdinfo = open(fdinfo_buf, O_RDONLY);
	if (fdinfo < 0) {
		pr_perror("Can't open  %d (%d)", p->fd, lfd);
		return -1;
	}

	ret = read(fdinfo, fdinfo_buf, sizeof(fdinfo_buf));
	close(fdinfo);

	if (ret <= 0) {
		pr_perror("Reading inotify from %d (%d) failed", p->fd, lfd);
		return -1;
	}

	ret = -1;

	if (write_img(image_fd, &ie))
		goto err;

	pos = strstr(fdinfo_buf, "wd:");
	if (!pos)
		goto parse_error;

	tok = strtok(pos, "\n");
	while (tok) {
		pr_debug("Line: `%s'\n", tok);
		ret = sscanf(tok,
			     "wd: %8d ino: %16lx, sdev: %8x mask %8x "
			     "fhandle-bytes: %8x fhandle-type: %8x f_handle: ",
			     &we.wd, &we.i_ino, &we.s_dev, &we.mask,
			     &we.f_handle.bytes, &we.f_handle.type);
		if (ret != 6) {
			pr_err("Inotify fdinfo format mismatch #%d\n", ret);
			goto parse_error;
		}

		pos = strstr(tok, "f_handle: ");
		if (!pos)
			goto parse_error;
		tok = pos + 10;

		parse_fhandle_encoded(tok, &we.f_handle);

		pr_info("inotify: id 0x%08x flags 0x%08x wd 0x%08x s_dev 0x%08x i_ino 0x%16lx mask 0x%08x\n",
			ie.id, ie.flags, we.wd, we.s_dev, we.i_ino, we.mask);
		pr_info("\t[fhandle] bytes 0x%08x type 0x%08x __handle 0x%016lx:0x%016lx\n",
			we.f_handle.bytes, we.f_handle.type,
			we.f_handle.__handle[0], we.f_handle.__handle[1]);

		if (write_img(image_wd, &we))
			goto err;

		tok = strtok(NULL, "\n");
	}

	ret = 0;
err:
	return ret;

parse_error:
	pr_err("Incorrect format in inotify fdinfo %d (%d)\n", p->fd, lfd);
	goto err;
}

static int restore_one_inotify(int inotify_fd, struct inotify_wd_entry *iwe)
{
	char path[32];
	int mntfd, ret = -1;
	int i, wd, target;

	mntfd = open_mount(iwe->s_dev);
	if (mntfd < 0) {
		pr_err("Mount root for 0x%08x not found\n", iwe->s_dev);
		return -1;
	}

	target = sys_open_by_handle_at(mntfd, (void *)&iwe->f_handle, 0);
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
	struct file_desc *p;
	int tmp;

	info = container_of(d, struct inotify_file_info, d);

	tmp = inotify_init1(info->ife.flags);
	if (tmp < 0) {
		pr_perror("Can't create inotify for 0x%08x", info->ife.id);
		return -1;
	}

	list_for_each_entry(wd_info, &info->marks, list) {
		pr_info("\tRestore inotify for 0x%08x\n", wd_info->iwe.id);
		if (restore_one_inotify(tmp, &wd_info->iwe)) {
			close_safe(&tmp);
			break;
		}
	}

	if (restore_fown(tmp, &info->ife.fown))
		close_safe(&tmp);

	return tmp;
}

static struct file_desc_ops desc_ops = {
	.open = open_inotify_fd,
};

static int collect_mark(struct inotify_wd_info *mark)
{
	struct inotify_file_info *p;

	list_for_each_entry(p, &info_head, list) {
		if (p->ife.id == mark->iwe.id) {
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
		struct inotify_file_entry ife;

		ret = read_img_eof(image_fd, &ife);
		if (ret < 0)
			goto err;
		else if (!ret)
			break;

		info = xmalloc(sizeof(*info));
		if (!info)
			return -1;

		info->ife = ife;
		INIT_LIST_HEAD(&info->list);
		INIT_LIST_HEAD(&info->marks);

		list_add(&info->list, &info_head);
	}

	image_wd = open_image_ro(CR_FD_INOTIFY_WD);
	if (image_wd < 0)
		goto err;

	while (1) {
		int idx;

		mark = xmalloc(sizeof(*mark));
		if (!mark)
			goto err;
		ret = read_img_eof(image_wd, &mark->iwe);
		if (ret < 0)
			goto err;
		else if (!ret)
			break;

		if (collect_mark(mark)) {
			ret = -1;
			pr_err("Can't find inotify with id 0x%08x\n", mark->iwe.id);
			goto err;
		}
	}

	list_for_each_entry(info, &info_head, list) {
		pr_info("Collected inotify: id 0x%08x flags 0x%08x\n", info->ife.id, info->ife.flags);
		file_desc_add(&info->d, FDINFO_INOTIFY, info->ife.id, &desc_ops);
	}
	ret = 0;
err:
	close_safe(&image_wd);
	close_safe(&image_fd);

	return ret;
}
