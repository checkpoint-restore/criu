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

#include "crtools.h"
#include "compiler.h"
#include "asm/types.h"
#include "imgset.h"
#include "rst_info.h"
#include "eventpoll.h"
#include "fdinfo.h"
#include "image.h"
#include "util.h"
#include "log.h"

#include "protobuf.h"
#include "images/eventpoll.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "epoll: "

struct eventpoll_file_info {
	EventpollFileEntry		*efe;
	struct file_desc		d;
};

struct eventpoll_tfd_file_info {
	EventpollTfdEntry		*tdefe;
	struct list_head		list;
};

static LIST_HEAD(eventpoll_tfds);

/* Checks if file descriptor @lfd is eventfd */
int is_eventpoll_link(char *link)
{
	return is_anon_link_type(link, "[eventpoll]");
}

static void pr_info_eventpoll_tfd(char *action, EventpollTfdEntry *e)
{
	pr_info("%seventpoll-tfd: id %#08x tfd %#08x events %#08x data %#016"PRIx64"\n",
		action, e->id, e->tfd, e->events, e->data);
}

static void pr_info_eventpoll(char *action, EventpollFileEntry *e)
{
	pr_info("%seventpoll: id %#08x flags %#04x\n", action, e->id, e->flags);
}

struct eventpoll_list {
	struct list_head list;
	int n;
};

static int dump_eventpoll_entry(union fdinfo_entries *e, void *arg)
{
	struct eventpoll_list *ep_list = (struct eventpoll_list *) arg;
	EventpollTfdEntry *efd = &e->epl.e;

	pr_info_eventpoll_tfd("Dumping: ", efd);

	list_add_tail(&e->epl.node, &ep_list->list);
	ep_list->n++;

	return 0;
}

static int dump_one_eventpoll(int lfd, u32 id, const struct fd_parms *p)
{
	EventpollFileEntry e = EVENTPOLL_FILE_ENTRY__INIT;
	struct eventpoll_list ep_list = {LIST_HEAD_INIT(ep_list.list), 0};
	union fdinfo_entries *te, *tmp;
	int i, ret = -1;

	e.id = id;
	e.flags = p->flags;
	e.fown = (FownEntry *)&p->fown;

	if (parse_fdinfo(lfd, FD_TYPES__EVENTPOLL, dump_eventpoll_entry, &ep_list))
		goto out;

	e.tfd = xmalloc(sizeof(struct EventpollTfdEntry *) * ep_list.n);
	if (!e.tfd)
		goto out;

	i = 0;
	list_for_each_entry(te, &ep_list.list, epl.node)
		e.tfd[i++] = &te->epl.e;
	e.n_tfd = ep_list.n;

	pr_info_eventpoll("Dumping ", &e);
	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_EVENTPOLL_FILE),
		     &e, PB_EVENTPOLL_FILE);
out:
	list_for_each_entry_safe(te, tmp, &ep_list.list, epl.node)
		free_event_poll_entry(te);

	return ret;
}

const struct fdtype_ops eventpoll_dump_ops = {
	.type		= FD_TYPES__EVENTPOLL,
	.dump		= dump_one_eventpoll,
};

static int eventpoll_open(struct file_desc *d)
{
	struct eventpoll_file_info *info;
	int tmp;

	info = container_of(d, struct eventpoll_file_info, d);

	pr_info_eventpoll("Restore ", info->efe);

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

	return tmp;
err_close:
	close(tmp);
	return -1;
}
static int eventpoll_retore_tfd(int fd, int id, EventpollTfdEntry *tdefe)
{
	struct epoll_event event;

	pr_info_eventpoll_tfd("Restore ", tdefe);

	event.events	= tdefe->events;
	event.data.u64	= tdefe->data;
	if (epoll_ctl(fd, EPOLL_CTL_ADD, tdefe->tfd, &event)) {
		pr_perror("Can't add event on %#08x", id);
		return -1;
	}

	return 0;
}

static int eventpoll_post_open(struct file_desc *d, int fd)
{
	struct eventpoll_tfd_file_info *td_info;
	struct eventpoll_file_info *info;
	int i;

	info = container_of(d, struct eventpoll_file_info, d);

	for (i = 0; i < info->efe->n_tfd; i++) {
		if (eventpoll_retore_tfd(fd, info->efe->id, info->efe->tfd[i]))
			return -1;
	}

	list_for_each_entry(td_info, &eventpoll_tfds, list) {
		if (td_info->tdefe->id != info->efe->id)
			continue;

		if (eventpoll_retore_tfd(fd, info->efe->id, td_info->tdefe))
			return -1;

	}

	return 0;
}

static void eventpoll_collect_fd(struct file_desc *d,
		struct fdinfo_list_entry *fle, struct rst_info *ri)
{
	list_add_tail(&fle->ps_list, &ri->eventpoll);
}

static struct file_desc_ops desc_ops = {
	.type = FD_TYPES__EVENTPOLL,
	.open = eventpoll_open,
	.post_open = eventpoll_post_open,
	.collect_fd = eventpoll_collect_fd,
};

static int collect_one_epoll_tfd(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct eventpoll_tfd_file_info *info = o;

	if (!deprecated_ok("Epoll TFD image"))
		return -1;

	info->tdefe = pb_msg(msg, EventpollTfdEntry);
	list_add(&info->list, &eventpoll_tfds);
	pr_info_eventpoll_tfd("Collected ", info->tdefe);

	return 0;
}

struct collect_image_info epoll_tfd_cinfo = {
	.fd_type = CR_FD_EVENTPOLL_TFD,
	.pb_type = PB_EVENTPOLL_TFD,
	.priv_size = sizeof(struct eventpoll_tfd_file_info),
	.collect = collect_one_epoll_tfd,
};

static int collect_one_epoll(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct eventpoll_file_info *info = o;

	info->efe = pb_msg(msg, EventpollFileEntry);
	pr_info_eventpoll("Collected ", info->efe);
	return file_desc_add(&info->d, info->efe->id, &desc_ops);
}

struct collect_image_info epoll_cinfo = {
	.fd_type = CR_FD_EVENTPOLL_FILE,
	.pb_type = PB_EVENTPOLL_FILE,
	.priv_size = sizeof(struct eventpoll_file_info),
	.collect = collect_one_epoll,
};
