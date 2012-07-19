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
#include "proc_parse.h"
#include "crtools.h"
#include "image.h"
#include "util.h"
#include "log.h"

#include "protobuf.h"
#include "protobuf/eventfd.pb-c.h"

struct eventfd_file_info {
	EventfdFileEntry		*efe;
	struct file_desc		d;
};

/* Checks if file desciptor @lfd is eventfd */
int is_eventfd_link(int lfd)
{
	return is_anon_link_type(lfd, "[eventfd]");
}

static void pr_info_eventfd(char *action, EventfdFileEntry *efe)
{
	pr_info("%seventfd: id %#08x flags %#04x counter %#016lx\n",
		action, efe->id, efe->flags, efe->counter);
}

void show_eventfds(int fd, struct cr_options *o)
{
	pb_show_plain(fd, eventfd_file_entry);
}

struct eventfd_dump_arg {
	u32 id;
	const struct fd_parms *p;
	bool dumped;
};

static int dump_eventfd_entry(union fdinfo_entries *e, void *arg)
{
	struct eventfd_dump_arg *da = arg;

	if (da->dumped) {
		pr_err("Several counters in a file?\n");
		return -1;
	}

	da->dumped = true;
	e->efd.id = da->id;
	e->efd.flags = da->p->flags;
	e->efd.fown = (FownEntry *)&da->p->fown;

	pr_info_eventfd("Dumping ", &e->efd);
	return pb_write(fdset_fd(glob_fdset, CR_FD_EVENTFD),
			&e->efd, eventfd_file_entry);
}

static int dump_one_eventfd(int lfd, u32 id, const struct fd_parms *p)
{
	struct eventfd_dump_arg da = { .id = id, .p = p, };
	return parse_fdinfo(lfd, FD_TYPES__EVENTFD, dump_eventfd_entry, &da);
}

static const struct fdtype_ops eventfd_ops = {
	.type		= FD_TYPES__EVENTFD,
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
	int tmp;

	info = container_of(d, struct eventfd_file_info, d);

	tmp = eventfd(info->efe->counter, 0);
	if (tmp < 0) {
		pr_perror("Can't create eventfd %#08x",
			  info->efe->id);
		return -1;
	}

	if (rst_file_params(tmp, info->efe->fown, info->efe->flags)) {
		pr_perror("Can't restore params on eventfd %#08x",
			  info->efe->id);
		goto err_close;
	}

	return tmp;

err_close:
	close(tmp);
	return -1;
}

static struct file_desc_ops eventfd_desc_ops = {
	.type = FD_TYPES__EVENTFD,
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

		ret = pb_read_eof(image_fd, &info->efe, eventfd_file_entry);
		if (ret < 0)
			goto err;
		else if (!ret)
			break;
		pr_info_eventfd("Collected ", info->efe);
		file_desc_add(&info->d, info->efe->id, &eventfd_desc_ops);
	}

err:
	xfree(info ? info->efe : NULL);
	xfree(info);
	close(image_fd);
	return ret;
}
