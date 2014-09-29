#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/timerfd.h>
#include <sys/ioctl.h>

#include "protobuf.h"
#include "protobuf/timerfd.pb-c.h"

#include "proc_parse.h"
#include "rst-malloc.h"
#include "cr_options.h"
#include "restorer.h"
#include "timerfd.h"
#include "pstree.h"
#include "files.h"
#include "imgset.h"
#include "util.h"
#include "log.h"
#include "bug.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "timerfd: "

struct timerfd_dump_arg {
	u32			id;
	const struct fd_parms	*p;
};

struct timerfd_info {
	TimerfdEntry		*tfe;
	struct file_desc	d;
};

struct restore_timerfd *rst_timerfd;
unsigned int rst_timerfd_nr;

int check_timerfd(void)
{
	int fd, ret = -1;

	if (opts.check_ms_kernel) {
		pr_warn("Skipping timerfd support check\n");
		return 0;
	}

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

static int dump_timerfd_entry(union fdinfo_entries *e, void *arg)
{
	struct timerfd_dump_arg *da = arg;
	TimerfdEntry *tfy = &e->tfy;

	tfy->id		= da->id;
	tfy->flags	= da->p->flags;
	tfy->fown	= (FownEntry *)&da->p->fown;

	pr_info("Dumping id %#x clockid %d it_value(%llu, %llu) it_interval(%llu, %llu)\n",
		tfy->id, tfy->clockid, (unsigned long long)tfy->vsec, (unsigned long long)tfy->vnsec,
		(unsigned long long)tfy->isec, (unsigned long long)tfy->insec);

	return pb_write_one(img_from_set(glob_imgset, CR_FD_TIMERFD), &e->tfy, PB_TIMERFD);
}

static int dump_one_timerfd(int lfd, u32 id, const struct fd_parms *p)
{
	struct timerfd_dump_arg da = { .id = id, .p = p, };
	return parse_fdinfo(lfd, FD_TYPES__TIMERFD, dump_timerfd_entry, &da);
}

const struct fdtype_ops timerfd_dump_ops = {
	.type		= FD_TYPES__TIMERFD,
	.dump		= dump_one_timerfd,
};

/*
 * We need to restore timers at the very late stage in restorer
 * to eliminate the case when timer is expired but we have not
 * yet finished restore procedure and signal handlers are not
 * set up properly. We need to copy timers settings into restorer
 * area that's why post-open is used for.
 */
static int timerfd_post_open(struct file_desc *d, int fd)
{
	struct timerfd_info *info = container_of(d, struct timerfd_info, d);
	TimerfdEntry *tfe = info->tfe;
	struct restore_timerfd *t;

	rst_timerfd_nr++;
	rst_timerfd = xrealloc(rst_timerfd, rst_timerfd_len());
	if (!rst_timerfd)
		return -ENOMEM;

	t = &rst_timerfd[rst_timerfd_nr - 1];
	t->id				= tfe->id;
	t->fd				= fd;
	t->clockid			= tfe->clockid;
	t->ticks			= (unsigned long)tfe->ticks;
	t->settime_flags		= tfe->settime_flags;
	t->val.it_interval.tv_sec	= (time_t)tfe->isec;
	t->val.it_interval.tv_nsec	= (long)tfe->insec;
	t->val.it_value.tv_sec		= (time_t)tfe->vsec;
	t->val.it_value.tv_nsec		= (long)tfe->vnsec;

	return 0;
}

static int timerfd_open(struct file_desc *d)
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

	return tmp;

err_close:
	close_safe(&tmp);
	return -1;
}

static struct file_desc_ops timerfd_desc_ops = {
	.type		= FD_TYPES__TIMERFD,
	.open		= timerfd_open,
	.post_open	= timerfd_post_open,
};

static int verify_timerfd(TimerfdEntry *tfe)
{
	if (tfe->clockid != CLOCK_REALTIME &&
	    tfe->clockid != CLOCK_MONOTONIC) {
		pr_err("Unknown clock type %d for %#x\n", tfe->clockid, tfe->id);
		return -1;
	}

	return 0;
}

static int collect_one_timerfd(void *o, ProtobufCMessage *msg)
{
	struct timerfd_info *info = o;

	info->tfe = pb_msg(msg, TimerfdEntry);
	if (verify_timerfd(info->tfe)) {
		pr_err("Verification failed for %#x\n", info->tfe->id);
		return -1;
	}

	return file_desc_add(&info->d, info->tfe->id, &timerfd_desc_ops);
}

struct collect_image_info timerfd_cinfo = {
	.fd_type	= CR_FD_TIMERFD,
	.pb_type	= PB_TIMERFD,
	.priv_size	= sizeof(struct timerfd_info),
	.collect	= collect_one_timerfd,
	.flags		= COLLECT_OPTIONAL,
};
