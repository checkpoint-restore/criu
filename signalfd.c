#include <unistd.h>
#include <signal.h>
#include <sys/signalfd.h>

#include "compiler.h"
#include "asm/types.h"
#include "signalfd.h"
#include "proc_parse.h"
#include "crtools.h"
#include "image.h"
#include "util.h"
#include "log.h"
#include "files.h"

#include "protobuf.h"
#include "protobuf/signalfd.pb-c.h"

struct signalfd_info {
	SignalfdEntry		*sfe;
	struct file_desc	d;
};

int is_signalfd_link(int lfd)
{
	return is_anon_link_type(lfd, "[signalfd]");
}

struct signalfd_dump_arg {
	u32 id;
	const struct fd_parms *p;
	bool dumped;
};

void show_signalfd(int fd)
{
	pb_show_plain(fd, PB_SIGNALFD);
}

static int dump_signalfd_entry(union fdinfo_entries *e, void *arg)
{
	struct signalfd_dump_arg *da = arg;

	if (da->dumped) {
		pr_err("Several counters in a file?\n");
		return -1;
	}

	da->dumped = true;
	e->sfd.id = da->id;
	e->sfd.flags = da->p->flags;
	e->sfd.fown = (FownEntry *)&da->p->fown;

	return pb_write_one(fdset_fd(glob_fdset, CR_FD_SIGNALFD),
			&e->sfd, PB_SIGNALFD);
}

static int dump_one_signalfd(int lfd, u32 id, const struct fd_parms *p)
{
	struct signalfd_dump_arg da = { .id = id, .p = p, };
	return parse_fdinfo(lfd, FD_TYPES__SIGNALFD, dump_signalfd_entry, &da);
}

const struct fdtype_ops signalfd_dump_ops = {
	.type		= FD_TYPES__SIGNALFD,
	.dump		= dump_one_signalfd,
};

static void sigset_fill(sigset_t *to, unsigned long long from)
{
	int sig;

	pr_info("\tCalculating sigmask for %Lx\n", from);
	sigemptyset(to);
	for (sig = 1; sig < NSIG; sig++)
		if (from & (1ULL << (sig - 1))) {
			pr_debug("\t\tAdd %d signal to mask\n", sig);
			sigaddset(to, sig);
		}
}

static int signalfd_open(struct file_desc *d)
{
	struct signalfd_info *info;
	int tmp;
	sigset_t mask;

	info = container_of(d, struct signalfd_info, d);
	pr_info("Restoring signalfd %#x\n", info->sfe->id);

	sigset_fill(&mask, info->sfe->sigmask);
	tmp = signalfd(-1, &mask, 0);
	if (tmp < 0) {
		pr_perror("Can't create signalfd %#08x", info->sfe->id);
		return -1;
	}

	if (rst_file_params(tmp, info->sfe->fown, info->sfe->flags)) {
		pr_perror("Can't restore params on signalfd %#08x",
			  info->sfe->id);
		goto err_close;
	}

	return tmp;

err_close:
	close(tmp);
	return -1;
}

static struct file_desc_ops signalfd_desc_ops = {
	.type = FD_TYPES__SIGNALFD,
	.open = signalfd_open,
};

static int collect_one_sigfd(void *o, ProtobufCMessage *msg)
{
	struct signalfd_info *info = o;

	info->sfe = pb_msg(msg, SignalfdEntry);
	file_desc_add(&info->d, info->sfe->id, &signalfd_desc_ops);

	return 0;
}

int collect_signalfd(void)
{
	int ret = collect_image(CR_FD_SIGNALFD, PB_SIGNALFD,
			sizeof(struct signalfd_info), collect_one_sigfd);

	if (ret < 0 && errno == ENOENT)
		return 0;

	return ret;
}
