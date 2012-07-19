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
#include <sys/epoll.h>

#include "compiler.h"
#include "types.h"
#include "eventpoll.h"
#include "proc_parse.h"
#include "crtools.h"
#include "image.h"
#include "util.h"
#include "log.h"

#include "protobuf.h"
#include "protobuf/eventpoll.pb-c.h"

struct eventpoll_file_info {
	EventpollFileEntry		*efe;
	struct file_desc		d;
};

struct eventpoll_tfd_file_info {
	EventpollTfdEntry		*tdefe;
	struct list_head		list;
};

static LIST_HEAD(eventpoll_tfds);

/* Checks if file desciptor @lfd is eventfd */
int is_eventpoll_link(int lfd)
{
	return is_anon_link_type(lfd, "[eventpoll]");
}

static void pr_info_eventpoll_tfd(char *action, EventpollTfdEntry *e)
{
	pr_info("%seventpoll-tfd: id %#08x tfd %#08x events %#08x data %#016lx\n",
		action, e->id, e->tfd, e->events, e->data);
}

static void pr_info_eventpoll(char *action, EventpollFileEntry *e)
{
	pr_info("%seventpoll: id %#08x flags %#04x\n", action, e->id, e->flags);
}

void show_eventpoll_tfd(int fd, struct cr_options *o)
{
	pb_show_plain(fd, eventpoll_tfd_entry);
}

void show_eventpoll(int fd, struct cr_options *o)
{
	pb_show_plain(fd, eventpoll_file_entry);
}

static int dump_eventpoll_entry(union fdinfo_entries *e, void *arg)
{
	EventpollTfdEntry *efd = &e->epl;

	efd->id = *(u32 *)arg;
	pr_info_eventpoll_tfd("Dumping: ", efd);
	return pb_write(fdset_fd(glob_fdset, CR_FD_EVENTPOLL_TFD),
			efd, eventpoll_tfd_entry);
}

static int dump_one_eventpoll(int lfd, u32 id, const struct fd_parms *p)
{
	EventpollFileEntry e = EVENTPOLL_FILE_ENTRY__INIT;

	e.id = id;
	e.flags = p->flags;
	e.fown = (FownEntry *)&p->fown;

	pr_info_eventpoll("Dumping ", &e);
	if (pb_write(fdset_fd(glob_fdset, CR_FD_EVENTPOLL),
		     &e, eventpoll_file_entry))
		return -1;

	return parse_fdinfo(lfd, FD_TYPES__EVENTPOLL, dump_eventpoll_entry, &id);
}

static const struct fdtype_ops eventpoll_ops = {
	.type		= FD_TYPES__EVENTPOLL,
	.make_gen_id	= make_gen_id,
	.dump		= dump_one_eventpoll,
};

int dump_eventpoll(struct fd_parms *p, int lfd, const struct cr_fdset *set)
{
	return do_dump_gen_file(p, lfd, &eventpoll_ops, set);
}

static int eventpoll_open(struct file_desc *d)
{
	struct eventpoll_tfd_file_info *td_info;
	struct eventpoll_file_info *info;
	int tmp, ret;

	info = container_of(d, struct eventpoll_file_info, d);

	tmp = epoll_create(1);
	if (tmp < 0) {
		pr_perror("Can't create epoll %#08x",
			  info->efe->id);
		return -1;
	}

	if (rst_file_params(tmp, info->efe->fown, info->efe->flags)) {
		pr_perror("Can't restore file params on epoll %#08x",
			  info->efe->id);
		goto err_close;
	}

	list_for_each_entry(td_info, &eventpoll_tfds, list) {
		struct epoll_event event;

		if (td_info->tdefe->id != info->efe->id)
			continue;

		event.events	= td_info->tdefe->events;
		event.data.u64	= td_info->tdefe->data;
		ret = epoll_ctl(tmp, EPOLL_CTL_ADD, td_info->tdefe->tfd, &event);
		if (ret) {
			pr_perror("Can't add event on %#08x", info->efe->id);
			goto err_close;
		}
	}

	return tmp;

err_close:
	close(tmp);
	return -1;
}

static struct file_desc_ops desc_ops = {
	.type = FD_TYPES__EVENTPOLL,
	.open = eventpoll_open,
};

int collect_eventpoll(void)
{
	int image_fd;
	int ret = -1;

	image_fd = open_image_ro(CR_FD_EVENTPOLL_TFD);
	if (image_fd < 0)
		return -1;

	while (1) {
		struct eventpoll_tfd_file_info *info;

		info = xmalloc(sizeof(*info));
		if (info) {
			info->tdefe = xmalloc(sizeof(*info->tdefe));
			if (!info->tdefe)
				goto err;
		} else
			goto err;

		ret = pb_read_eof(image_fd, &info->tdefe, eventpoll_tfd_entry);
		if (ret < 0)
			goto err;
		else if (!ret)
			break;

		INIT_LIST_HEAD(&info->list);

		list_add(&info->list, &eventpoll_tfds);
		pr_info_eventpoll_tfd("Collected ", info->tdefe);
	}

	close_safe(&image_fd);

	image_fd = open_image_ro(CR_FD_EVENTPOLL);
	if (image_fd < 0)
		return -1;

	while (1) {
		struct eventpoll_file_info *info;

		ret = -1;
		info = xmalloc(sizeof(*info));
		if (!info)
			goto err;

		ret = pb_read_eof(image_fd, &info->efe, eventpoll_file_entry);
		if (ret < 0)
			goto err;
		else if (!ret)
			break;

		pr_info_eventpoll("Collected ", info->efe);
		file_desc_add(&info->d, info->efe->id, &desc_ops);
	}

err:
	close_safe(&image_fd);
	return ret;
}
