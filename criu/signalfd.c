#include <unistd.h>
#include <signal.h>
#include <sys/signalfd.h>

#include "common/compiler.h"
#include "signalfd.h"
#include "fdinfo.h"
#include "imgset.h"
#include "image.h"
#include "util.h"
#include "log.h"
#include "files.h"

#include "protobuf.h"
#include "images/signalfd.pb-c.h"

struct signalfd_info {
	SignalfdEntry *sfe;
	struct file_desc d;
};

int is_signalfd_link(char *link)
{
	return is_anon_link_type(link, "[signalfd]");
}

static int dump_one_signalfd(int lfd, u32 id, const struct fd_parms *p)
{
	SignalfdEntry sfd = SIGNALFD_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;

	if (parse_fdinfo(lfd, FD_TYPES__SIGNALFD, &sfd))
		return -1;

	sfd.id = id;
	sfd.flags = p->flags;
	sfd.fown = (FownEntry *)&p->fown;

	fe.type = FD_TYPES__SIGNALFD;
	fe.id = sfd.id;
	fe.sgfd = &sfd;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);
}

const struct fdtype_ops signalfd_dump_ops = {
	.type = FD_TYPES__SIGNALFD,
	.dump = dump_one_signalfd,
};

static void sigset_fill(sigset_t *to, unsigned long long from)
{
	int sig;

	pr_info("\tCalculating sigmask for %llx\n", from);
	sigemptyset(to);
	for (sig = 1; sig < NSIG; sig++)
		if (from & (1ULL << (sig - 1))) {
			pr_debug("\t\tAdd %d signal to mask\n", sig);
			sigaddset(to, sig);
		}
}

static int signalfd_open(struct file_desc *d, int *new_fd)
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
		pr_perror("Can't restore params on signalfd %#08x", info->sfe->id);
		goto err_close;
	}

	*new_fd = tmp;
	return 0;

err_close:
	close(tmp);
	return -1;
}

static struct file_desc_ops signalfd_desc_ops = {
	.type = FD_TYPES__SIGNALFD,
	.open = signalfd_open,
};

static int collect_one_sigfd(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct signalfd_info *info = o;

	info->sfe = pb_msg(msg, SignalfdEntry);
	return file_desc_add(&info->d, info->sfe->id, &signalfd_desc_ops);
}

struct collect_image_info signalfd_cinfo = {
	.fd_type = CR_FD_SIGNALFD,
	.pb_type = PB_SIGNALFD,
	.priv_size = sizeof(struct signalfd_info),
	.collect = collect_one_sigfd,
};
