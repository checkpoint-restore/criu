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
#include "asm/types.h"
#include "fdset.h"
#include "rst_info.h"
#include "eventpoll.h"
#include "proc_parse.h"
#include "image.h"
#include "util.h"
#include "log.h"

#include "protobuf.h"
#include "protobuf/eventpoll.pb-c.h"

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
int is_eventpoll_link(int lfd)
{
	return is_anon_link_type(lfd, "[eventpoll]");
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

static int dump_eventpoll_entry(union fdinfo_entries *e, void *arg)
{
	EventpollTfdEntry *efd = &e->epl;

	efd->id = *(u32 *)arg;
	pr_info_eventpoll_tfd("Dumping: ", efd);
	return pb_write_one(fdset_fd(glob_fdset, CR_FD_EVENTPOLL_TFD),
			efd, PB_EVENTPOLL_TFD);
}

static int dump_one_eventpoll(int lfd, u32 id, const struct fd_parms *p)
{
	EventpollFileEntry e = EVENTPOLL_FILE_ENTRY__INIT;

	e.id = id;
	e.flags = p->flags;
	e.fown = (FownEntry *)&p->fown;

	pr_info_eventpoll("Dumping ", &e);
	if (pb_write_one(fdset_fd(glob_fdset, CR_FD_EVENTPOLL_FILE),
		     &e, PB_EVENTPOLL_FILE))
		return -1;

	return parse_fdinfo(lfd, FD_TYPES__EVENTPOLL, dump_eventpoll_entry, &id);
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

static int eventpoll_post_open(struct file_desc *d, int fd)
{
	int ret;
	struct eventpoll_tfd_file_info *td_info;
	struct eventpoll_file_info *info;

	info = container_of(d, struct eventpoll_file_info, d);

	list_for_each_entry(td_info, &eventpoll_tfds, list) {
		struct epoll_event event;

		if (td_info->tdefe->id != info->efe->id)
			continue;

		pr_info_eventpoll_tfd("Restore ", td_info->tdefe);

		event.events	= td_info->tdefe->events;
		event.data.u64	= td_info->tdefe->data;
		ret = epoll_ctl(fd, EPOLL_CTL_ADD, td_info->tdefe->tfd, &event);
		if (ret) {
			pr_perror("Can't add event on %#08x", info->efe->id);
			return -1;
		}
	}

	return 0;
}

static struct list_head *eventpoll_select_list(struct file_desc *d, struct rst_info *ri)
{
	return &ri->eventpoll;
}

static struct file_desc_ops desc_ops = {
	.type = FD_TYPES__EVENTPOLL,
	.open = eventpoll_open,
	.post_open = eventpoll_post_open,
	.select_ps_list = eventpoll_select_list,
};

static int collect_one_epoll_tfd(void *o, ProtobufCMessage *msg)
{
	struct eventpoll_tfd_file_info *info = o;

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

static int collect_one_epoll(void *o, ProtobufCMessage *msg)
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
