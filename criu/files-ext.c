/* An external file is a file, which is dumped with help a plugin */

#include <unistd.h>

#include "imgset.h"
#include "files.h"
#include "plugin.h"

#include "protobuf.h"
#include "images/ext-file.pb-c.h"

static int dump_one_ext_file(int lfd, u32 id, const struct fd_parms *p)
{
	int ret;
	struct cr_img *rimg;
	FileEntry fe = FILE_ENTRY__INIT;
	ExtFileEntry xfe = EXT_FILE_ENTRY__INIT;

	ret = run_plugins(DUMP_EXT_FILE, lfd, id);
	if (ret < 0)
		return ret;

	xfe.id		= id;
	xfe.fown	= (FownEntry *)&p->fown;

	fe.type = FD_TYPES__EXT;
	fe.id = xfe.id;
	fe.ext = &xfe;

	rimg = img_from_set(glob_imgset, CR_FD_FILES);
	return pb_write_one(rimg, &fe, PB_FILE);
}

const struct fdtype_ops ext_dump_ops = {
	.type		= FD_TYPES__EXT,
	.dump		= dump_one_ext_file,
};

struct ext_file_info {
	struct file_desc	d;
	ExtFileEntry		*xfe;
};

static int open_fd(struct file_desc *d, int *new_fd)
{
	struct ext_file_info *xfi;
	int fd;

	xfi = container_of(d, struct ext_file_info, d);

	fd = run_plugins(RESTORE_EXT_FILE, xfi->xfe->id);
	if (fd < 0) {
		pr_err("Unable to restore %#x\n", xfi->xfe->id);
		return -1;
	}

	if (restore_fown(fd, xfi->xfe->fown))
		return -1;

	*new_fd = fd;
	return 0;
}

static struct file_desc_ops ext_desc_ops = {
	.type = FD_TYPES__EXT,
	.open = open_fd,
};

static int collect_one_ext(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct ext_file_info *xfi = o;

	xfi->xfe = pb_msg(base, ExtFileEntry);

	pr_info("Collected external file with ID %#x\n", xfi->xfe->id);
	return file_desc_add(&xfi->d, xfi->xfe->id, &ext_desc_ops);
}

struct collect_image_info ext_file_cinfo = {
	.fd_type = CR_FD_EXT_FILES,
	.pb_type = PB_EXT_FILE,
	.priv_size = sizeof(struct ext_file_info),
	.collect = collect_one_ext,
};

int dump_unsupp_fd(struct fd_parms *p, int lfd,
		char *more, char *info, FdinfoEntry *e)
{
	int ret;

	ret = do_dump_gen_file(p, lfd, &ext_dump_ops, e);
	if (ret == 0)
		return 0;
	if (ret == -ENOTSUP)
		pr_err("Can't dump file %d of that type [%o] (%s %s)\n",
			p->fd, p->stat.st_mode, more, info);
	return -1;
}
