#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>

#include "compiler.h"
#include "types.h"
#include "eventfd.h"

#include "crtools.h"
#include "image.h"
#include "util.h"
#include "log.h"

struct eventfd_file_info {
	struct eventfd_file_entry	efe;
	struct file_desc		d;
};

/* Checks if file desciptor @lfd is eventfd */
int is_eventfd_link(int lfd)
{
	return is_anon_link_type(lfd, "[eventfd]");
}

static void pr_info_eventfd(char *action, struct eventfd_file_entry *efe)
{
	pr_info("%seventfd: id %#08x flags %#04x counter %#016lx\n",
		action, efe->id, efe->flags, efe->counter);
}

void show_eventfds(int fd, struct cr_options *o)
{
	struct eventfd_file_entry efe;

	pr_img_head(CR_FD_EVENTFD);

	while (1) {
		int ret;

		ret = read_img_eof(fd, &efe);
		if (ret <= 0)
			goto out;
		pr_msg("id: %#08x flags %#04x counter: %#016lx ",
		       efe.id, efe.flags, efe.counter);
		show_fown_cont(&efe.fown);
		pr_msg("\n");
	}

out:
	pr_img_tail(CR_FD_EVENTFD);
}

static int dump_one_eventfd(int lfd, u32 id, const struct fd_parms *p)
{
	int image_fd = fdset_fd(glob_fdset, CR_FD_EVENTFD);
	struct eventfd_file_entry efe;
	char buf[64];
	char *pos;
	int ret, fdinfo;

	efe.id		= id;
	efe.flags	= p->flags;
	efe.fown	= p->fown;

	snprintf(buf, sizeof(buf), "/proc/self/fdinfo/%d", lfd);
	fdinfo = open(buf, O_RDONLY);
	if (fdinfo < 0) {
		pr_perror("Can't open  %d (%d)", p->fd, lfd);
		return -1;
	}

	ret = read(fdinfo, buf, sizeof(buf));
	close(fdinfo);

	if (ret <= 0) {
		pr_perror("Reading eventfd from %d (%d) failed", p->fd, lfd);
		return -1;
	}

	pos = strstr(buf, "count-raw:");
	if (!pos || !sscanf(pos, "count-raw: %lx", &efe.counter)) {
		pr_err("Counter value is not found for %d (%d)\n", p->fd, lfd);
		return -1;
	}

	pr_info_eventfd("Dumping ", &efe);
	if (write_img(image_fd, &efe))
		return -1;

	return 0;
}

static const struct fdtype_ops eventfd_ops = {
	.type		= FDINFO_EVENTFD,
	.make_gen_id	= make_gen_id,
	.dump		= dump_one_eventfd,
};

int dump_eventfd(struct fd_parms *p, int lfd, const struct cr_fdset *set)
{
	return do_dump_gen_file(p, lfd, &eventfd_ops, set);
}

static int eventfd_open(struct file_desc *d)
{
	struct eventfd_file_info *info;
	size_t size;
	int tmp;

	info = container_of(d, struct eventfd_file_info, d);

	tmp = eventfd(info->efe.counter, 0);
	if (tmp < 0) {
		pr_perror("Can't create eventfd %#08x",
			  info->efe.id);
		return -1;
	}

	if (rst_file_params(tmp, &info->efe.fown, info->efe.flags)) {
		pr_perror("Can't restore params on eventfd %#08x",
			  info->efe.id);
		goto err_close;
	}

	return tmp;

err_close:
	close(tmp);
	return -1;
}

static struct file_desc_ops eventfd_desc_ops = {
	.open = eventfd_open,
};

int collect_eventfd(void)
{
	struct eventfd_file_info *info = NULL;
	int ret, image_fd;

	image_fd = open_image_ro(CR_FD_EVENTFD);
	if (image_fd < 0)
		return -1;

	while (1) {
		ret = -1;

		info = xmalloc(sizeof(*info));
		if (!info)
			break;

		ret = read_img_eof(image_fd, &info->efe);
		if (ret < 0)
			goto err;
		else if (!ret)
			break;
		pr_info_eventfd("Collected ", &info->efe);
		file_desc_add(&info->d, FDINFO_EVENTFD, info->efe.id, &eventfd_desc_ops);
	}

err:
	xfree(info);
	close(image_fd);
	return ret;
}
