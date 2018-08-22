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

#include "types.h"
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
#include "parasite.h"
#include "kerndat.h"
#include "file-ids.h"
#include "kcmp-ids.h"

#include "protobuf.h"
#include "images/eventpoll.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "epoll: "

static LIST_HEAD(dinfo_list);

typedef struct {
	uint32_t			tfd;
	uint32_t			off;
	uint32_t			idx;
} toff_t;

struct eventpoll_dinfo {
	struct list_head		list;

	FileEntry			*fe;
	EventpollFileEntry		*e;

	toff_t				*toff;
	FownEntry			fown;

	pid_t				pid;
	int				efd;
};

struct eventpoll_file_info {
	EventpollFileEntry		*efe;
	struct file_desc		d;
};

/* Checks if file descriptor @lfd is eventfd */
int is_eventpoll_link(char *link)
{
	return is_anon_link_type(link, "[eventpoll]");
}

static void pr_info_eventpoll_tfd(char *action, uint32_t id, EventpollTfdEntry *e)
{
	pr_info("%seventpoll-tfd: id %#08x tfd %8d events %#08x data %#016"PRIx64"\n",
		action, id, e->tfd, e->events, e->data);
}

static void pr_info_eventpoll(char *action, EventpollFileEntry *e)
{
	pr_info("%seventpoll: id %#08x flags %#04x\n", action, e->id, e->flags);
}

static int queue_dinfo(FileEntry **fe, EventpollFileEntry **e, toff_t **toff, const struct fd_parms *p)
{
	struct eventpoll_dinfo *dinfo;

	pr_info_eventpoll("Queueing ", *e);

	dinfo = xmalloc(sizeof(*dinfo));
	if (!dinfo)
		return -ENOMEM;

	memcpy(&dinfo->fown, &p->fown, sizeof(dinfo->fown));

	INIT_LIST_HEAD(&dinfo->list);

	dinfo->fe	= *fe;
	dinfo->e	= *e;
	dinfo->toff	= *toff;
	dinfo->e->fown	= &dinfo->fown;
	dinfo->pid	= p->pid;
	dinfo->efd	= p->fd;

	*fe	= NULL;
	*e	= NULL;
	*toff	= NULL;

	list_add_tail(&dinfo->list, &dinfo_list);
	return 0;
}

static void dequeue_dinfo(struct eventpoll_dinfo *dinfo)
{
	ssize_t i;

	for (i = 0; i < dinfo->e->n_tfd; i++)
		eventpoll_tfd_entry__free_unpacked(dinfo->e->tfd[i], NULL);

	xfree(dinfo->fe);
	xfree(dinfo->e->tfd);
	xfree(dinfo->e);
	xfree(dinfo->toff);

	list_del(&dinfo->list);

	xfree(dinfo);
}

int flush_eventpoll_dinfo_queue(void)
{
	struct eventpoll_dinfo *dinfo, *t;
	ssize_t i;

	list_for_each_entry_safe(dinfo, t, &dinfo_list, list) {
		EventpollFileEntry *e = dinfo->e;

		for (i = 0; i < e->n_tfd; i++) {
			EventpollTfdEntry *tfde = e->tfd[i];
			struct kid_elem ke = {
				.pid	= dinfo->pid,
				.genid	= make_gen_id(tfde->dev,
						      tfde->inode,
						      tfde->pos),
				.idx	= tfde->tfd,
			};
			kcmp_epoll_slot_t slot = {
				.efd	= dinfo->efd,
				.tfd	= tfde->tfd,
				.toff	= dinfo->toff[i].off,
			};
			struct kid_elem *t = kid_lookup_epoll_tfd(&fd_tree, &ke, &slot);
			if (!t) {
				pr_debug("kid_lookup_epoll: no match pid %d efd %d tfd %d toff %u\n",
					 dinfo->pid, dinfo->efd, tfde->tfd, dinfo->toff[i].off);
				goto err;
			}

			pr_debug("kid_lookup_epoll: rbsearch match pid %d efd %d tfd %d toff %u -> %d\n",
				 dinfo->pid, dinfo->efd, tfde->tfd, dinfo->toff[i].off, t->idx);

			/* Make sure the pid matches */
			if (t->pid != dinfo->pid) {
				pr_debug("kid_lookup_epoll: pid mismatch %d %d efd %d tfd %d toff %u\n",
					 dinfo->pid, t->pid, dinfo->efd, tfde->tfd, dinfo->toff[i].off);
				goto err;
			}

			tfde->tfd = t->idx;
		}

		pr_info_eventpoll("Dumping ", e);
		if (pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), dinfo->fe, PB_FILE))
			goto err;

		for (i = 0; i < e->n_tfd; i++)
			pr_info_eventpoll_tfd("Dumping: ", e->id, e->tfd[i]);

		dequeue_dinfo(dinfo);
	}

	return 0;

err:
	list_for_each_entry_safe(dinfo, t, &dinfo_list, list)
		dequeue_dinfo(dinfo);

	return -1;
}

static int tfd_cmp(const void *a, const void *b)
{
	if (((int *)a)[0] > ((int *)b)[0])
		return 1;
	if (((int *)a)[0] < ((int *)b)[0])
		return -1;
	return 0;
}

static int toff_cmp(const void *a, const void *b)
{
	if (((toff_t *)a)[0].tfd > ((toff_t *)b)[0].tfd)
		return 1;
	if (((toff_t *)a)[0].tfd < ((toff_t *)b)[0].tfd)
		return -1;
	if (((toff_t *)a)[0].idx > ((toff_t *)b)[0].idx)
		return 1;
	if (((toff_t *)a)[0].idx < ((toff_t *)b)[0].idx)
		return -1;
	return 0;
}

/*
 * fds in fd_parms are sorted so we can use binary search
 * for better performance.
 */
static int find_tfd_bsearch(pid_t pid, int efd, int fds[], size_t nr_fds,
			    int tfd, unsigned int toff)
{
	kcmp_epoll_slot_t slot = {
		.efd	= efd,
		.tfd	= tfd,
		.toff	= toff,
	};
	int *tfd_found;

	pr_debug("find_tfd_bsearch: pid %d efd %d tfd %d toff %u\n", pid, efd, tfd, toff);

	/*
	 * Optimistic case: the target fd belongs to us
	 * and wasn't dup'ed.
	 */
	tfd_found = bsearch(&tfd, fds, nr_fds, sizeof(int), tfd_cmp);
	if (tfd_found) {
		if (kdat.has_kcmp_epoll_tfd) {
			if (syscall(SYS_kcmp, pid, pid, KCMP_EPOLL_TFD, tfd, &slot) == 0) {
				pr_debug("find_tfd_bsearch (kcmp-yes): bsearch match pid %d efd %d tfd %d toff %u\n",
					 pid, efd, tfd, toff);
				return tfd;
			}
		} else {
			pr_debug("find_tfd_bsearch (kcmp-no): bsearch match pid %d efd %d tfd %d toff %u\n",
				 pid, efd, tfd, toff);
			return tfd;
		}
	}

	pr_debug("find_tfd_bsearch: no match pid %d efd %d tfd %d toff %u\n",
		 pid, efd, tfd, toff);
	return -1;
}

static int dump_one_eventpoll(int lfd, u32 id, const struct fd_parms *p)
{
	toff_t *toff_base, *toff = NULL;
	EventpollFileEntry *e = NULL;
	FileEntry *fe = NULL;
	int ret = -1;
	ssize_t i;

	e = xmalloc(sizeof(*e));
	if (!e)
		goto out;
	eventpoll_file_entry__init(e);

	fe = xmalloc(sizeof(*fe));
	if (!fe)
		goto out;
	file_entry__init(fe);

	e->id		= id;
	e->flags	= p->flags;
	e->fown		= (FownEntry *)&p->fown;

	if (parse_fdinfo(lfd, FD_TYPES__EVENTPOLL, e))
		goto out;

	fe->type	= FD_TYPES__EVENTPOLL;
	fe->id		= e->id;
	fe->epfd	= e;

	/*
	 * In regular case there is no so many dup'ed
	 * descriptors so instead of complex mappings
	 * lets rather walk over members with O(n^2)
	 */
	if (p->dfds) {
		toff = xmalloc(sizeof(*toff) * e->n_tfd);
		if (!toff)
			goto out;
		for (i = 0; i < e->n_tfd; i++) {
			toff[i].idx	= i;
			toff[i].tfd	= e->tfd[i]->tfd;
			toff[i].off	= 0;
		}

		qsort(toff, e->n_tfd, sizeof(*toff), toff_cmp);

		toff_base = NULL;
		for (i = 1; i < e->n_tfd; i++) {
			if (toff[i].tfd == toff[i - 1].tfd) {
				if (!toff_base)
					toff_base = &toff[i - 1];
				toff[i].off = toff[i].idx - toff_base->idx;
			} else
				toff_base = NULL;
		}
	}

	/*
	 * Handling dup'ed or transferred target
	 * files is tricky: we need to use kcmp
	 * to find out where file came from. Until
	 * it's implemented lets use simpler approach
	 * just check the targets are blonging to the
	 * pid's file set.
	 */
	if (p->dfds) {
		for (i = 0; i < e->n_tfd; i++) {
			int tfd = find_tfd_bsearch(p->pid, p->fd, p->dfds->fds,
						   p->dfds->nr_fds, e->tfd[i]->tfd, toff[i].off);
			if (tfd == -1) {
				if (kdat.has_kcmp_epoll_tfd) {
					ret = queue_dinfo(&fe, &e, &toff, p);
				} else {
					pr_err("Escaped/closed fd descriptor %d on pid %d\n",
					       e->tfd[i]->tfd, p->pid);
				}
				goto out;
			}
		}
	} else
		pr_warn_once("Unix SCM files are not verified\n");

	pr_info_eventpoll("Dumping ", e);
	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), fe, PB_FILE);
	if (!ret) {
		for (i = 0; i < e->n_tfd; i++)
			pr_info_eventpoll_tfd("Dumping: ", e->id, e->tfd[i]);
	}

out:
	for (i = 0; e && i < e->n_tfd; i++)
		eventpoll_tfd_entry__free_unpacked(e->tfd[i], NULL);
	xfree(fe);
	if (e)
		xfree(e->tfd);
	xfree(e);
	xfree(toff);

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

	pr_info_eventpoll_tfd("Restore ", id, tdefe);

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
	.type		= FD_TYPES__EVENTPOLL,
	.open		= eventpoll_open,
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
	.fd_type	= CR_FD_EVENTPOLL_TFD,
	.pb_type	= PB_EVENTPOLL_TFD,
	.collect	= collect_one_epoll_tfd,
	.flags		= COLLECT_NOFREE,
};

static int collect_one_epoll(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct eventpoll_file_info *info = o;

	info->efe = pb_msg(msg, EventpollFileEntry);
	pr_info_eventpoll("Collected ", info->efe);
	return file_desc_add(&info->d, info->efe->id, &desc_ops);
}

struct collect_image_info epoll_cinfo = {
	.fd_type	= CR_FD_EVENTPOLL_FILE,
	.pb_type	= PB_EVENTPOLL_FILE,
	.priv_size	= sizeof(struct eventpoll_file_info),
	.collect	= collect_one_epoll,
};
