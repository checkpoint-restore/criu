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
#include "asm/types.h"
#include "eventfd.h"
#include "proc_parse.h"
#include "crtools.h"
#include "image.h"
#include "util.h"
#include "log.h"

#include "protobuf.h"
#include "protobuf/eventfd.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "eventfd: "

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
	pr_info("%s: id %#08x flags %#04x counter %#016"PRIx64"\n",
		action, efe->id, efe->flags, efe->counter);
}

void show_eventfds(int fd, struct cr_options *o)
{
	pb_show_plain(fd, PB_EVENTFD);
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
	return pb_write_one(fdset_fd(glob_fdset, CR_FD_EVENTFD),
			&e->efd, PB_EVENTFD);
}

static int dump_one_eventfd(int lfd, u32 id, const struct fd_parms *p)
{
	struct eventfd_dump_arg da = { .id = id, .p = p, };
	return parse_fdinfo(lfd, FD_TYPES__EVENTFD, dump_eventfd_entry, &da);
}

static const struct fdtype_ops eventfd_ops = {
	.type		= FD_TYPES__EVENTFD,
	.dump		= dump_one_eventfd,
};

int dump_eventfd(struct fd_parms *p, int lfd, const int fdinfo)
{
	return do_dump_gen_file(p, lfd, &eventfd_ops, fdinfo);
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

static int collect_one_efd(void *obj, ProtobufCMessage *msg)
{
	struct eventfd_file_info *info = obj;

	info->efe = pb_msg(msg, EventfdFileEntry);
	file_desc_add(&info->d, info->efe->id, &eventfd_desc_ops);
	pr_info_eventfd("Collected ", info->efe);

	return 0;
}

int collect_eventfd(void)
{
	return collect_image(CR_FD_EVENTFD, PB_EVENTFD,
			sizeof(struct eventfd_file_info), collect_one_efd);
}
