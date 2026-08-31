#include <unistd.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include "imgset.h"
#include "image.h"
#include "files.h"
#include "files-reg.h"
#include "file-ids.h"
#include "pipes.h"

#include "fifo.h"

#include "protobuf.h"
#include "images/regfile.pb-c.h"
#include "images/fifo.pb-c.h"

/*
 * FIFO checkpoint and restore is done in a bit unusual manner.
 * We use files-reg.c engine to save fifo path and flags,
 * thus regular files image will contain fifo descriptors which
 * are useless for reg-files engine itself but needed for our fifo
 * engine.
 *
 * In particular we dump fifo-entry automatically and appropriate
 * reg-file entry manually, thus on restore we need to ask reg-file
 * engine to restore fifo path and flags via direct call.
 */

struct fifo_info {
	struct list_head list;
	struct file_desc d;
	FifoEntry *fe;
	bool restore_data;
};

static LIST_HEAD(fifo_head);
static struct pipe_data_dump pd_fifo = {
	.img_type = CR_FD_FIFO_DATA,
};

/*
 * fifo_open() latches pipe->w_counter into filp->f_version for a
 * non-blocking read-only end opened with no writer around, and
 * pipe_poll() suppresses POLLHUP while the two still match. An end
 * that has not seen a writer and one whose writer is gone for good
 * differ nowhere else, so ask poll().
 */
static int fifo_wait_writer(int lfd)
{
	struct pollfd pfd = {
		.fd = lfd,
		.events = POLLIN,
	};
	int ret;

	ret = poll(&pfd, 1, 0);
	if (ret < 0) {
		pr_perror("Can't poll fifo");
		return -1;
	}

	return !(ret > 0 && (pfd.revents & POLLHUP));
}

static int dump_one_fifo(int lfd, u32 id, const struct fd_parms *p)
{
	struct cr_img *img = img_from_set(glob_imgset, CR_FD_FILES);
	FileEntry fe = FILE_ENTRY__INIT;
	FifoEntry e = FIFO_ENTRY__INIT;
	u32 rf_id;

	fd_id_generate_special(NULL, &rf_id);

	/*
	 * It's a trick here, we use regular files dumping
	 * code to save path to a fifo, then we reuse it
	 * on restore.
	 */
	if (dump_one_reg_file(lfd, rf_id, p))
		return -1;

	pr_info("Dumping fifo %d with id %#x pipe_id %#x\n", lfd, id, pipe_id(p));

	e.id = id;
	e.pipe_id = pipe_id(p);
	e.has_regf_id = true;
	e.regf_id = rf_id;

	if ((p->flags & O_ACCMODE) == O_RDONLY) {
		int wait_writer = fifo_wait_writer(lfd);

		if (wait_writer < 0)
			return -1;

		e.has_wait_writer = true;
		e.wait_writer = wait_writer;
	}

	fe.type = FD_TYPES__FIFO;
	fe.id = e.id;
	fe.fifo = &e;

	if (pb_write_one(img, &fe, PB_FILE))
		return -1;

	return dump_one_pipe_data(&pd_fifo, lfd, p);
}

const struct fdtype_ops fifo_dump_ops = {
	.type = FD_TYPES__FIFO,
	.dump = dump_one_fifo,
};

static struct pipe_data_rst *pd_hash_fifo[PIPE_DATA_HASH_SIZE];

static bool fifo_has_data(u32 id)
{
	struct pipe_data_rst *pd;

	for (pd = pd_hash_fifo[id & PIPE_DATA_HASH_MASK]; pd != NULL; pd = pd->next)
		if (pd->pde->pipe_id == id)
			return pd->pde->bytes > 0;

	return false;
}

static int do_open_fifo(int ns_root_fd, struct reg_file_info *rfi, void *arg)
{
	struct fifo_info *info = arg;
	int new_fifo = -1, fake_fifo = -1;
	int flags = rfi->rfe->flags;

	bool read_only = (flags & O_ACCMODE) == O_RDONLY;
	bool nonblocking = flags & O_NONBLOCK;
	bool pipe_empty = !fifo_has_data(info->fe->pipe_id);
	bool wait_writer = info->fe->has_wait_writer && info->fe->wait_writer;

	/*
	 * An end which had not seen a writer has to be opened with no
	 * writer around too, or it comes back as a closed pipe and the
	 * application polling it spins. Such an end never blocks on open,
	 * so it needs no fake writer at all, and opening one would bump
	 * w_counter and hang up the ends restored before it. A fifo with
	 * buffered data is left alone, as the fake writer is the one
	 * holding the data.
	 */
	bool skip_fake_writer = read_only && nonblocking && pipe_empty && wait_writer;

	/*
	 * FIFOs (except read-write FIFOs) block until the other end is
	 * opened. Open a temporary read-write descriptor so the restore
	 * process can proceed.
	 */
	if (!skip_fake_writer) {
		fake_fifo = openat(ns_root_fd, rfi->path, O_RDWR);
		if (fake_fifo < 0) {
			pr_perror("Can't open fake fifo %#x [%s]", info->fe->id, rfi->path);
			return -1;
		}

		if (info->restore_data) {
			if (restore_pipe_data(CR_FD_FIFO_DATA, fake_fifo, info->fe->pipe_id, pd_hash_fifo))
				goto out;
		}
	}

	new_fifo = openat(ns_root_fd, rfi->path, flags);
	if (new_fifo < 0) {
		pr_perror("Can't open fifo %#x [%s]", info->fe->id, rfi->path);
		goto out;
	}

	/*
	 * With no fake writer around there is nothing else holding the pipe,
	 * so its parameters are restored on the final descriptor instead.
	 * The fifo carries no data in this case, so this only restores the
	 * pipe size, which works on a read-only descriptor too.
	 */
	if (info->restore_data && skip_fake_writer) {
		if (restore_pipe_data(CR_FD_FIFO_DATA, new_fifo, info->fe->pipe_id, pd_hash_fifo)) {
			close(new_fifo);
			new_fifo = -1;
		}
	}

out:
	close_safe(&fake_fifo);
	return new_fifo;
}

static int open_fifo_fd(struct file_desc *d, int *new_fd)
{
	struct fifo_info *info = container_of(d, struct fifo_info, d);
	struct file_desc *reg_d;
	int fd;

	reg_d = collect_special_file(info->fe->has_regf_id ? info->fe->regf_id : info->fe->id);
	if (!reg_d)
		return -1;

	fd = open_path(reg_d, do_open_fifo, info);
	if (fd < 0)
		return -1;
	*new_fd = fd;
	return 0;
}

static struct file_desc_ops fifo_desc_ops = {
	.type = FD_TYPES__FIFO,
	.open = open_fifo_fd,
};

static int collect_one_fifo(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct fifo_info *info = o, *f;

	info->fe = pb_msg(base, FifoEntry);
	pr_info("Collected fifo entry ID %#x PIPE ID %#x\n", info->fe->id, info->fe->pipe_id);

	/* check who will restore the fifo data */
	list_for_each_entry(f, &fifo_head, list)
		if (f->fe->pipe_id == info->fe->pipe_id)
			break;

	if (&f->list == &fifo_head) {
		list_add(&info->list, &fifo_head);
		info->restore_data = true;
	} else {
		INIT_LIST_HEAD(&info->list);
		info->restore_data = false;
	}

	return file_desc_add(&info->d, info->fe->id, &fifo_desc_ops);
}

struct collect_image_info fifo_cinfo = {
	.fd_type = CR_FD_FIFO,
	.pb_type = PB_FIFO,
	.priv_size = sizeof(struct fifo_info),
	.collect = collect_one_fifo,
};

static int collect_fifo_data(void *obj, ProtobufCMessage *msg, struct cr_img *img)
{
	return do_collect_pipe_data(obj, msg, img, pd_hash_fifo);
}

struct collect_image_info fifo_data_cinfo = {
	.fd_type = CR_FD_FIFO_DATA,
	.pb_type = PB_PIPE_DATA,
	.priv_size = sizeof(struct pipe_data_rst),
	.collect = collect_fifo_data,
};
