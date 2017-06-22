#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/timerfd.h>
#include <sys/ioctl.h>

#include "protobuf.h"
#include "images/timerfd.pb-c.h"

#include "fdinfo.h"
#include "rst-malloc.h"
#include "cr_options.h"
#include "restorer.h"
#include "timerfd.h"
#include "pstree.h"
#include "files.h"
#include "imgset.h"
#include "util.h"
#include "log.h"
#include "common/bug.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "timerfd: "

struct timerfd_dump_arg {
	u32			id;
	const struct fd_parms	*p;
};

struct timerfd_info {
	TimerfdEntry		*tfe;
	struct file_desc	d;
	int			t_fd;
	struct list_head	rlist;
};

static LIST_HEAD(rst_timerfds);

int check_timerfd(void)
{
	int fd, ret = -1;

	fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (fd < 0) {
		pr_perror("timerfd_create failed");
		return -1;
	} else {
		ret = ioctl(fd, TFD_IOC_SET_TICKS, NULL);
		if (ret < 0) {
			if (errno != EFAULT)
				pr_perror("No timerfd support for c/r");
			else
				ret = 0;
		}
	}

	close(fd);
	return ret;
}

int is_timerfd_link(char *link)
{
	return is_anon_link_type(link, "[timerfd]");
}

static int dump_one_timerfd(int lfd, u32 id, const struct fd_parms *p)
{
	TimerfdEntry tfe = TIMERFD_ENTRY__INIT;

	if (parse_fdinfo(lfd, FD_TYPES__TIMERFD, &tfe))
		return -1;

	tfe.id = id;
	tfe.flags = p->flags;
	tfe.fown = (FownEntry *)&p->fown;
	pr_info("Dumping id %#x clockid %d it_value(%llu, %llu) it_interval(%llu, %llu)\n",
		tfe.id, tfe.clockid, (unsigned long long)tfe.vsec, (unsigned long long)tfe.vnsec,
		(unsigned long long)tfe.isec, (unsigned long long)tfe.insec);

	return pb_write_one(img_from_set(glob_imgset, CR_FD_TIMERFD), &tfe, PB_TIMERFD);
}

const struct fdtype_ops timerfd_dump_ops = {
	.type		= FD_TYPES__TIMERFD,
	.dump		= dump_one_timerfd,
};

int prepare_timerfds(struct task_restore_args *ta)
{
	struct timerfd_info *ti;
	struct restore_timerfd *t;

	ta->timerfd = (struct restore_timerfd *)rst_mem_align_cpos(RM_PRIVATE);
	ta->timerfd_n = 0;

	list_for_each_entry(ti, &rst_timerfds, rlist) {
		TimerfdEntry *tfe = ti->tfe;

		t = rst_mem_alloc(sizeof(*t), RM_PRIVATE);
		if (!t)
			return -1;

		t->id				= tfe->id;
		t->fd				= ti->t_fd;
		t->clockid			= tfe->clockid;
		t->ticks			= (unsigned long)tfe->ticks;
		t->settime_flags		= tfe->settime_flags;
		t->val.it_interval.tv_sec	= (time_t)tfe->isec;
		t->val.it_interval.tv_nsec	= (long)tfe->insec;
		t->val.it_value.tv_sec		= (time_t)tfe->vsec;
		t->val.it_value.tv_nsec		= (long)tfe->vnsec;

		ta->timerfd_n++;
	}

	return 0;
}

static int timerfd_open(struct file_desc *d, int *new_fd)
{
	struct timerfd_info *info;
	TimerfdEntry *tfe;
	int tmp = -1;

	info = container_of(d, struct timerfd_info, d);
	tfe = info->tfe;
	pr_info("Creating timerfd id %#x clockid %d settime_flags %x ticks %llu "
		"it_value(%llu, %llu) it_interval(%llu, %llu)\n",
		tfe->id, tfe->clockid, tfe->settime_flags, (unsigned long long)tfe->ticks,
		(unsigned long long)tfe->vsec, (unsigned long long)tfe->vnsec,
		(unsigned long long)tfe->isec, (unsigned long long)tfe->insec);

	tmp = timerfd_create(tfe->clockid, 0);
	if (tmp < 0) {
		pr_perror("Can't create for %#x", tfe->id);
		return -1;
	}

	if (rst_file_params(tmp, tfe->fown, tfe->flags)) {
		pr_perror("Can't restore params for %#x", tfe->id);
		goto err_close;
	}

	info->t_fd = file_master(d)->fe->fd;
	list_add_tail(&info->rlist, &rst_timerfds);

	*new_fd = tmp;
	return 0;

err_close:
	close_safe(&tmp);
	return -1;
}

static struct file_desc_ops timerfd_desc_ops = {
	.type		= FD_TYPES__TIMERFD,
	.open		= timerfd_open,
};

static int collect_one_timerfd(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct timerfd_info *info = o;

	info->tfe = pb_msg(msg, TimerfdEntry);
	if (verify_timerfd(info->tfe)) {
		pr_err("Verification failed for %#x\n", info->tfe->id);
		return -1;
	}

	info->t_fd = -1;

	return file_desc_add(&info->d, info->tfe->id, &timerfd_desc_ops);
}

struct collect_image_info timerfd_cinfo = {
	.fd_type	= CR_FD_TIMERFD,
	.pb_type	= PB_TIMERFD,
	.priv_size	= sizeof(struct timerfd_info),
	.collect	= collect_one_timerfd,
};
