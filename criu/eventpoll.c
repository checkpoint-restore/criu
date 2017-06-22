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
#include "common/compiler.h"
#include "imgset.h"
#include "rst_info.h"
#include "eventpoll.h"
#include "fdinfo.h"
#include "image.h"
#include "util.h"
#include "log.h"
#include "pstree.h"

#include "protobuf.h"
#include "images/eventpoll.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "epoll: "

struct eventpoll_file_info {
	EventpollFileEntry		*efe;
	struct file_desc		d;
};

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

static int dump_one_eventpoll(int lfd, u32 id, const struct fd_parms *p)
{
	EventpollFileEntry e = EVENTPOLL_FILE_ENTRY__INIT;
	int i, ret = -1;

	e.id = id;
	e.flags = p->flags;
	e.fown = (FownEntry *)&p->fown;

	if (parse_fdinfo(lfd, FD_TYPES__EVENTPOLL, &e))
		goto out;

	pr_info_eventpoll("Dumping ", &e);
	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_EVENTPOLL_FILE),
		     &e, PB_EVENTPOLL_FILE);
out:
	for (i = 0; i < e.n_tfd; i++) {
		if (!ret)
			pr_info_eventpoll_tfd("Dumping: ", e.tfd[i]);
		eventpoll_tfd_entry__free_unpacked(e.tfd[i], NULL);
	}
	xfree(e.tfd);

	return ret;
}

const struct fdtype_ops eventpoll_dump_ops = {
	.type		= FD_TYPES__EVENTPOLL,
	.dump		= dump_one_eventpoll,
};

static int eventpoll_post_open(struct file_desc *d, int fd);

static int eventpoll_open(struct file_desc *d, int *new_fd)
{
	struct fdinfo_list_entry *fle = file_master(d);
	struct eventpoll_file_info *info;
	int tmp;

	info = container_of(d, struct eventpoll_file_info, d);

	if (fle->stage >= FLE_OPEN)
		return eventpoll_post_open(d, fle->fe->fd);

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

	*new_fd = tmp;
	return 1;
err_close:
	close(tmp);
	return -1;
}

static int epoll_not_ready_tfd(EventpollTfdEntry *tdefe)
{
	struct fdinfo_list_entry *fle;

	list_for_each_entry(fle, &rsti(current)->fds, ps_list) {
		if (tdefe->tfd != fle->fe->fd)
			continue;

		if (fle->desc->ops->type == FD_TYPES__EVENTPOLL)
			return (fle->stage < FLE_OPEN);
		else
			return (fle->stage != FLE_RESTORED);
	}

	/*
	 * If tgt fle is not on the fds list, it's already
	 * restored (see open_fdinfos), so we're ready.
	 */
	return 0;
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
	struct eventpoll_file_info *info;
	int i;

	info = container_of(d, struct eventpoll_file_info, d);

	for (i = 0; i < info->efe->n_tfd; i++) {
		if (epoll_not_ready_tfd(info->efe->tfd[i]))
			return 1;
	}
	for (i = 0; i < info->efe->n_tfd; i++) {
		if (eventpoll_retore_tfd(fd, info->efe->id, info->efe->tfd[i]))
			return -1;
	}

	return 0;
}

static struct file_desc_ops desc_ops = {
	.type = FD_TYPES__EVENTPOLL,
	.open = eventpoll_open,
};

static int collect_one_epoll_tfd(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	EventpollTfdEntry *tfde;
	struct file_desc *d;
	struct eventpoll_file_info *ef;
	EventpollFileEntry *efe;
	int n_tfd;

	if (!deprecated_ok("Epoll TFD image"))
		return -1;

	tfde = pb_msg(msg, EventpollTfdEntry);
	d = find_file_desc_raw(FD_TYPES__EVENTPOLL, tfde->id);
	if (!d) {
		pr_err("No epoll FD for %u\n", tfde->id);
		return -1;
	}

	ef = container_of(d, struct eventpoll_file_info, d);
	efe = ef->efe;

	n_tfd = efe->n_tfd + 1;
	if (xrealloc_safe(&efe->tfd, n_tfd * sizeof(EventpollTfdEntry *)))
		return -1;

	efe->tfd[efe->n_tfd] = tfde;
	efe->n_tfd = n_tfd;

	return 0;
}

struct collect_image_info epoll_tfd_cinfo = {
	.fd_type = CR_FD_EVENTPOLL_TFD,
	.pb_type = PB_EVENTPOLL_TFD,
	.collect = collect_one_epoll_tfd,
	.flags = COLLECT_NOFREE,
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
