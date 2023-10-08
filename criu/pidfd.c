#include "pidfd.h"
#include "util.h"

#include "fdinfo.h"
#include "files.h"
#include "imgset.h"
#include "protobuf.h"
#include "fdinfo.pb-c.h"

int is_pidfd_link(char *link)
{
	return is_anon_link_type(link, "[pidfd]");
}

static int dump_one_pidfd(int lfd, u32 id, const struct fd_parms *p)
{
	PidfdEntry tfe = PIDFD_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;

	if (parse_fdinfo(lfd, FD_TYPES__PIDFD, &tfe))
		return -1;

	tfe.id = id;
	tfe.flags = p->flags;
	tfe.inode = p->stat.st_ino;
	tfe.mnt_id = p->mnt_id;
	tfe.fown = (FownEntry *)&p->fown;

	fe.type = FD_TYPES__PIDFD;
	fe.id = tfe.id;
	fe.pidfd = &tfe;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);
}

const struct fdtype_ops pidfd_dump_ops = {
	.type = FD_TYPES__PIDFD,
	.dump = dump_one_pidfd,
};

struct pidfd_info {
	PidfdEntry *pidfde;
	struct file_desc d;
};

static int open_pidfd_fd(struct file_desc *d, int *new_fd)
{
	int fd = -1;
	struct pidfd_info *info = container_of(d, struct pidfd_info, d);
	PidfdEntry *pidfde = info->pidfde;

	pr_info("Creating new pidfd %" PRId64 "\n", pidfde->pid);
	fd = pidfd_open(pidfde->pid, 0);
	if (fd < 0) {
		pr_perror("Cannot create pidfd %" PRId64, pidfde->pid);
		return -1;
	}

	*new_fd = fd;
	return 0;
}

static struct file_desc_ops pidfd_desc_ops = {
	.type = FD_TYPES__PIDFD,
	.open = open_pidfd_fd,
};

static int collect_one_pidfd(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct pidfd_info *info = o;

	info->pidfde = pb_msg(msg, PidfdEntry);
	return file_desc_add(&info->d, info->pidfde->id, &pidfd_desc_ops);
}

struct collect_image_info pidfd_cinfo = {
	.fd_type = CR_FD_PIDFD,
	.pb_type = PB_PIDFD,
	.priv_size = sizeof(struct pidfd_info),
	.collect = collect_one_pidfd,
};
