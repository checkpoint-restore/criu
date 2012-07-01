#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include "crtools.h"
#include "image.h"
#include "files.h"
#include "files-reg.h"
#include "pipes.h"

#include "fifo.h"

/*
 * FIFO checkpoint and restore is done in a bit unusual manner.
 * We use files-reg.c engine to save fifo path and flags,
 * thus regular files image will contain fifo descriptos which
 * are useless for reg-files engine itself but needed for our fifo
 * engine.
 *
 * In particual we dump fifo-entry automatically and appropriate
 * reg-file entry manually, thus on restore we need to ask reg-file
 * engine to restore fifo path and flags via direct call.
 */

struct fifo_info {
	struct list_head	list;
	struct file_desc	d;
	struct fifo_entry	fe;

	u32			bytes;
	off_t			off;
	bool			restore_data;
};

static LIST_HEAD(fifo_head);

static int dump_one_fifo(int lfd, u32 id, const struct fd_parms *p)
{
	int img = fdset_fd(glob_fdset, CR_FD_FIFO);
	struct fifo_entry e;

	/*
	 * It's a trick here, we use regular files dumping
	 * code to save path to a fifo, then we reuse it
	 * on restore.
	 */
	if (dump_one_reg_file(lfd, id, p))
		return -1;

	pr_info("Dumping fifo %d with id %#x pipe_id %#x\n",
		lfd, id, (u32)p->stat.st_ino);

	e.id		= id;
	e.pipe_id	= p->stat.st_ino;

	if (write_img(img, &e) < 0)
		return -1;

	return dump_one_pipe_data(CR_FD_FIFO_DATA, lfd, id, p);
}

static const struct fdtype_ops fifo_ops = {
	.type		= FDINFO_FIFO,
	.make_gen_id	= make_gen_id,
	.dump		= dump_one_fifo,
};

int dump_fifo(struct fd_parms *p, int lfd, const struct cr_fdset *set)
{
	return do_dump_gen_file(p, lfd, &fifo_ops, set);
}

static int do_open_fifo(struct reg_file_info *rfi, void *arg)
{
	struct fifo_info *info = arg;
	int new_fifo, fake_fifo = -1;

	/*
	 * The fifos (except read-write fifos) do wait until
	 * another pipe-end get connected, so to be able to
	 * proceed the restoration procedure we open a fake
	 * fifo here.
	 */
	fake_fifo = open(rfi->path, O_RDWR);
	if (fake_fifo < 0) {
		pr_perror("Can't open fake fifo %#x [%s]", info->fe.id, rfi->path);
		return -1;
	}

	new_fifo = open(rfi->path, rfi->rfe.flags);
	if (new_fifo < 0) {
		pr_perror("Can't open fifo %#x [%s]", info->fe.id, rfi->path);
		goto out;
	}

	if (info->restore_data) {
		if (restore_pipe_data(CR_FD_FIFO_DATA, fake_fifo, info->fe.id,
				      info->bytes, info->off)) {
			close(new_fifo);
			new_fifo = -1;
		}
	}

out:
	close(fake_fifo);
	return new_fifo;
}

static int open_fifo_fd(struct file_desc *d)
{
	struct fifo_info *info = container_of(d, struct fifo_info, d);

	return open_path_by_id(info->fe.id, do_open_fifo, info);
}

static struct file_desc_ops fifo_desc_ops = {
	.type		= FDINFO_FIFO,
	.open		= open_fifo_fd,
};

static int handle_fifo_data(void)
{
	int img, ret;

	img = open_image_ro(CR_FD_FIFO_DATA);
	if (img < 0)
		return -1;

	while (1) {
		struct pipe_data_entry pde;
		struct fifo_info *info;

		ret = read_img_eof(img, &pde);
		if (ret <= 0)
			break;

		list_for_each_entry(info, &fifo_head, list) {
			if (info->fe.pipe_id != pde.pipe_id ||
			    info->restore_data)
				continue;

			info->off	= lseek(img, 0, SEEK_CUR) + pde.off;
			info->bytes	= pde.bytes;

			lseek(img, pde.bytes + pde.off, SEEK_CUR);

			info->restore_data = true;
			break;
		}
	}

	close(img);
	return ret;
}

int collect_fifo(void)
{
	struct fifo_info *info = NULL;
	int img, ret = -1;

	img = open_image_ro(CR_FD_FIFO);
	if (img < 0)
		return -1;

	while (1) {
		info = xzalloc(sizeof(*info));
		if (!info) {
			ret = -1;
			break;
		}

		ret = read_img_eof(img, &info->fe);
		if (ret <= 0)
			break;

		pr_info("Collected fifo entry ID %#x PIPE ID %#x\n",
			info->fe.id, info->fe.pipe_id);

		file_desc_add(&info->d, info->fe.id, &fifo_desc_ops);
		list_add(&info->list, &fifo_head);
	}

	if (!ret)
		ret = handle_fifo_data();

	xfree(info);
	close(img);

	return ret;
}
