#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "crtools.h"

#include "files.h"
#include "image.h"
#include "list.h"
#include "util.h"

#include "files-reg.h"

struct reg_file_info {
	struct reg_file_entry rfe;
	char *remap_path;
	char *path;
	struct file_desc d;
};

struct ghost_file {
	u32 id;
	char *path;
	struct list_head list;
};

/*
 * Ghost files are those not visible from the FS. Dumping them is
 * nasty and the only way we have -- just carry its contents with
 * us. Any brave soul to implement link unlinked file back?
 */
struct ghost_file_dumpee {
	u32	dev;
	u32	ino;
	u32	id;
	struct list_head list;
};

static u32 ghost_file_ids = 1;
static LIST_HEAD(ghost_files);

/*
 * This constant is selected without any calculations. Just do not
 * want to pick up too big files with us in the image.
 */
#define MAX_GHOST_FILE_SIZE	(1 * 1024 * 1024)

void clear_ghost_files(void)
{
	struct ghost_file *gf;

	pr_info("Unlinking ghosts\n");
	list_for_each_entry(gf, &ghost_files, list) {
		pr_info("\t`- %s\n", gf->path);
		unlink(gf->path);
	}
}

static int open_remap_ghost(struct reg_file_info *rfi,
		struct remap_file_path_entry *rfe)
{
	struct ghost_file *gf;
	struct ghost_file_entry gfe;
	int gfd, ifd;

	list_for_each_entry(gf, &ghost_files, list)
		if (gf->id == rfe->remap_id)
			goto gf_found;

	/*
	 * Ghost not found. We will create one in the same dir
	 * as the very first client of it thus resolving any
	 * issues with cross-device links.
	 */

	pr_info("Opening ghost file %#x for %s\n", rfe->remap_id, rfi->path);

	gf = xmalloc(sizeof(*gf));
	if (!gf)
		return -1;
	gf->path = xmalloc(PATH_MAX);
	if (!gf->path)
		return -1;

	ifd = open_image_ro(CR_FD_GHOST_FILE, rfe->remap_id);
	if (ifd < 0)
		return -1;

	if (read_img(ifd, &gfe) < 0)
		return -1;

	snprintf(gf->path, PATH_MAX, "%s.cr.%x.ghost", rfi->path, rfe->remap_id);
	gfd = open(gf->path, O_WRONLY | O_CREAT | O_EXCL, gfe.mode);
	if (gfd < 0) {
		pr_perror("Can't open ghost file");
		return -1;
	}

	if (fchown(gfd, gfe.uid, gfe.gid) < 0) {
		pr_perror("Can't reset user/group on ghost %#x\n", rfe->remap_id);
		return -1;
	}

	if (copy_file(ifd, gfd, 0) < 0)
		return -1;

	close(ifd);
	close(gfd);

	gf->id = rfe->remap_id;
	list_add_tail(&gf->list, &ghost_files);
gf_found:
	rfi->remap_path = gf->path;
	return 0;
}

static int collect_remaps(void)
{
	int fd, ret = 0;

	fd = open_image_ro(CR_FD_REMAP_FPATH);
	if (fd < 0)
		return -1;

	while (1) {
		struct remap_file_path_entry rfe;
		struct file_desc *fdesc;
		struct reg_file_info *rfi;

		ret = read_img_eof(fd, &rfe);
		if (ret <= 0)
			break;

		ret = -1;

		if (!(rfe.remap_id & REMAP_GHOST)) {
			pr_err("Non ghost remap not supported @%#x\n",
					rfe.orig_id);
			break;
		}

		fdesc = find_file_desc_raw(FDINFO_REG, rfe.orig_id);
		if (fdesc == NULL) {
			pr_err("Remap for non existing file %#x\n",
					rfe.orig_id);
			break;
		}

		rfe.remap_id &= ~REMAP_GHOST;
		rfi = container_of(fdesc, struct reg_file_info, d);
		pr_info("Configuring remap %#x -> %#x\n", rfi->rfe.id, rfe.remap_id);
		ret = open_remap_ghost(rfi, &rfe);
		if (ret < 0)
			break;
	}

	close(fd);
	return ret;
}

static int dump_ghost_file(int _fd, u32 id, const struct stat *st)
{
	int img, fd;
	struct ghost_file_entry gfe;
	char lpath[32];

	pr_info("Dumping ghost file contents (id %#x)\n", id);

	img = open_image(CR_FD_GHOST_FILE, O_DUMP, id);
	if (img < 0)
		return -1;

	/*
	 * Reopen file locally since it may have no read
	 * permissions when drained
	 */
	snprintf(lpath, sizeof(lpath), "/proc/self/fd/%d", _fd);
	fd = open(lpath, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open ghost original file");
		return -1;
	}

	gfe.uid = st->st_uid;
	gfe.gid = st->st_gid;
	gfe.mode = st->st_mode;

	if (write_img(img, &gfe))
		return -1;

	if (copy_file(fd, img, st->st_size))
		return -1;

	close(fd);
	close(img);
	return 0;
}

static int dump_ghost_remap(char *path, const struct stat *st, int lfd, u32 id)
{
	struct ghost_file_dumpee *gf;
	struct remap_file_path_entry rpe;

	pr_info("Dumping ghost file for fd %d id %#x\n", lfd, id);

	if (st->st_size > MAX_GHOST_FILE_SIZE) {
		pr_err("Can't dump ghost file %s of %lu size\n",
				path, st->st_size);
		return -1;
	}

	list_for_each_entry(gf, &ghost_files, list)
		if ((gf->dev == st->st_dev) && (gf->ino == st->st_ino))
			goto dump_entry;

	gf = xmalloc(sizeof(*gf));
	if (gf == NULL)
		return -1;

	gf->dev = st->st_dev;
	gf->ino = st->st_ino;
	gf->id = ghost_file_ids++;
	list_add_tail(&gf->list, &ghost_files);

	if (dump_ghost_file(lfd, gf->id, st))
		return -1;

dump_entry:
	rpe.orig_id = id;
	rpe.remap_id = gf->id | REMAP_GHOST;

	return write_img(fdset_fd(glob_fdset, CR_FD_REMAP_FPATH), &rpe);
}

static int check_path_remap(char *path, const struct stat *ost, int lfd, u32 id)
{
	int ret;
	struct stat pst;

	if (ost->st_nlink == 0)
		/*
		 * Unpleasant, but easy case. File is completely invisible
		 * from the FS. Just dump its contents and that's it. But
		 * be careful whether anybody still has any of its hardlinks
		 * also open.
		 */
		return dump_ghost_remap(path, ost, lfd, id);

	ret = stat(path, &pst);
	if (ret < 0) {
		/*
		 * FIXME linked file, but path is not accessible (unless any
		 * other error occurred). We can create a temporary link to it
		 * uning linkat with AT_EMPTY_PATH flag and remap it to this
		 * name.
		 */
		pr_perror("Can't stat path");
		return -1;
	}

	if ((pst.st_ino != ost->st_ino) || (pst.st_dev != ost->st_dev)) {
		/*
		 * FIXME linked file, but the name we see it by is reused
		 * by somebody else.
		 */
		pr_err("Unaccessible path opened %u:%u, need %u:%u\n",
				(int)pst.st_dev, (int)pst.st_ino,
				(int)ost->st_dev, (int)ost->st_ino);
		return -1;
	}

	/*
	 * File is linked and visible by the name it is opened by
	 * this task. Go ahead and dump it.
	 */
	return 0;
}


int dump_one_reg_file(int lfd, u32 id, const struct fd_parms *p)
{
	char fd_str[128];
	char path[PATH_MAX];
	int len, rfd;
	struct reg_file_entry rfe;

	snprintf(fd_str, sizeof(fd_str), "/proc/self/fd/%d", lfd);
	len = readlink(fd_str, path, sizeof(path) - 1);
	if (len < 0) {
		pr_perror("Can't readlink %s", fd_str);
		return len;
	}

	path[len] = '\0';
	pr_info("Dumping path for %d fd via self %d [%s]\n",
			p->fd, lfd, path);

	if (check_path_remap(path, &p->stat, lfd, id))
		return -1;

	rfe.len = len;
	rfe.flags = p->flags;
	rfe.pos = p->pos;
	rfe.id = id;
	rfe.fown = p->fown;

	rfd = fdset_fd(glob_fdset, CR_FD_REG_FILES);

	if (write_img(rfd, &rfe))
		return -1;
	if (write_img_buf(rfd, path, len))
		return -1;

	return 0;
}

static const struct fdtype_ops regfile_ops = {
	.type		= FDINFO_REG,
	.make_gen_id	= make_gen_id,
	.dump		= dump_one_reg_file,
};

int dump_reg_file(struct fd_parms *p, int lfd,
			     const struct cr_fdset *cr_fdset)
{
	return do_dump_gen_file(p, lfd, &regfile_ops, cr_fdset);
}

static int open_fe_fd(struct file_desc *d)
{
	struct reg_file_info *rfi;
	int tmp;

	rfi = container_of(d, struct reg_file_info, d);

	if (rfi->remap_path)
		if (link(rfi->remap_path, rfi->path) < 0) {
			pr_perror("Can't link %s -> %s\n",
					rfi->remap_path, rfi->path);
			return -1;
		}

	tmp = open(rfi->path, rfi->rfe.flags);
	if (tmp < 0) {
		pr_perror("Can't open file %s", rfi->path);
		return -1;
	}

	if (rfi->remap_path)
		unlink(rfi->path);

	lseek(tmp, rfi->rfe.pos, SEEK_SET);

	if (restore_fown(tmp, &rfi->rfe.fown))
		return -1;

	return tmp;
}

int open_reg_by_id(u32 id)
{
	struct file_desc *fd;

	fd = find_file_desc_raw(FDINFO_REG, id);
	if (fd == NULL) {
		pr_perror("Can't find regfile for %#x\n", id);
		return -1;
	}

	return open_fe_fd(fd);
}

static struct file_desc_ops reg_desc_ops = {
	.type = FDINFO_REG,
	.open = open_fe_fd,
};

int collect_reg_files(void)
{
	struct reg_file_info *rfi = NULL;
	int fd, ret = -1;

	fd = open_image_ro(CR_FD_REG_FILES);
	if (fd < 0)
		return -1;

	while (1) {
		int len;

		rfi = xmalloc(sizeof(*rfi));
		ret = -1;
		if (rfi == NULL)
			break;

		rfi->path = NULL;
		ret = read_img_eof(fd, &rfi->rfe);
		if (ret <= 0)
			break;

		len = rfi->rfe.len;
		rfi->path = xmalloc(len + 1);
		ret = -1;
		if (rfi->path == NULL)
			break;

		ret = read_img_buf(fd, rfi->path, len);
		if (ret < 0)
			break;

		rfi->remap_path = NULL;
		rfi->path[len] = '\0';

		pr_info("Collected [%s] ID %#x\n", rfi->path, rfi->rfe.id);
		file_desc_add(&rfi->d, rfi->rfe.id, &reg_desc_ops);
	}

	if (rfi) {
		xfree(rfi->path);
		xfree(rfi);
	}

	close(fd);

	return collect_remaps();
}
