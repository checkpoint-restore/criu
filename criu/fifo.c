#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include "imgset.h"
#include "image.h"
#include "files.h"
#include "files-reg.h"
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
	struct list_head	list;
	struct file_desc	d;
	FifoEntry		*fe;
	bool			restore_data;
	struct file_desc	*reg_d;
};

static LIST_HEAD(fifo_head);
static struct pipe_data_dump pd_fifo = { .img_type = CR_FD_FIFO_DATA, };

static int dump_one_fifo(int lfd, u32 id, const struct fd_parms *p)
{
	struct cr_img *img = img_from_set(glob_imgset, CR_FD_FIFO);
	FifoEntry e = FIFO_ENTRY__INIT;

	/*
	 * It's a trick here, we use regular files dumping
	 * code to save path to a fifo, then we reuse it
	 * on restore.
	 */
	if (dump_one_reg_file(lfd, id, p))
		return -1;

	pr_info("Dumping fifo %d with id %#x pipe_id %#x\n",
			lfd, id, pipe_id(p));

	e.id		= id;
	e.pipe_id	= pipe_id(p);

	if (pb_write_one(img, &e, PB_FIFO))
		return -1;

	return dump_one_pipe_data(&pd_fifo, lfd, p);
}

const struct fdtype_ops fifo_dump_ops = {
	.type		= FD_TYPES__FIFO,
	.dump		= dump_one_fifo,
};

static struct pipe_data_rst *pd_hash_fifo[PIPE_DATA_HASH_SIZE];

static int do_open_fifo(int ns_root_fd, struct reg_file_info *rfi, void *arg)
{
	struct fifo_info *info = arg;
	int new_fifo, fake_fifo = -1;

	/*
	 * The fifos (except read-write fifos) do wait until
	 * another pipe-end get connected, so to be able to
	 * proceed the restoration procedure we open a fake
	 * fifo here.
	 */
	fake_fifo = openat(ns_root_fd, rfi->path, O_RDWR);
	if (fake_fifo < 0) {
		pr_perror("Can't open fake fifo %#x [%s]", info->fe->id, rfi->path);
		return -1;
	}

	new_fifo = openat(ns_root_fd, rfi->path, rfi->rfe->flags);
	if (new_fifo < 0) {
		pr_perror("Can't open fifo %#x [%s]", info->fe->id, rfi->path);
		goto out;
	}

	if (info->restore_data)
		if (restore_pipe_data(CR_FD_FIFO_DATA, fake_fifo,
					info->fe->pipe_id, pd_hash_fifo)) {
			close(new_fifo);
			new_fifo = -1;
		}

out:
	close(fake_fifo);
	return new_fifo;
}

static int open_fifo_fd(struct file_desc *d)
{
	struct fifo_info *info = container_of(d, struct fifo_info, d);

	return open_path(info->reg_d, do_open_fifo, info);
}

static void collect_fifo_fd(struct file_desc *d,
		struct fdinfo_list_entry *fle, struct rst_info *ri)
{
	struct fifo_info *info;

	info = container_of(d, struct fifo_info, d);
	info->reg_d = collect_special_file(info->fe->id);
	BUG_ON(info->reg_d == NULL);
	collect_gen_fd(fle, ri);
}

static struct file_desc_ops fifo_desc_ops = {
	.type		= FD_TYPES__FIFO,
	.open		= open_fifo_fd,
	.collect_fd	= collect_fifo_fd,
};

static int collect_one_fifo(void *o, ProtobufCMessage *base)
{
	struct fifo_info *info = o, *f;

	info->fe = pb_msg(base, FifoEntry);
	pr_info("Collected fifo entry ID %#x PIPE ID %#x\n",
			info->fe->id, info->fe->pipe_id);

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

int collect_fifo(void)
{
	return collect_pipe_data(CR_FD_FIFO_DATA, pd_hash_fifo);
}
