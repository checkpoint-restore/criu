#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "crtools.h"
#include "file-ids.h"
#include "mount.h"
#include "files.h"
#include "image.h"
#include "list.h"
#include "util.h"
#include "asm/atomic.h"

#include "protobuf.h"
#include "protobuf/regfile.pb-c.h"
#include "protobuf/remap-file-path.pb-c.h"

#include "files-reg.h"

/*
 * Ghost files are those not visible from the FS. Dumping them is
 * nasty and the only way we have -- just carry its contents with
 * us. Any brave soul to implement link unlinked file back?
 */
struct ghost_file {
	struct list_head	list;
	u32			id;

	u32			dev;
	u32			ino;

	struct file_remap	remap;
};

static u32 ghost_file_ids = 1;
static LIST_HEAD(ghost_files);

static mutex_t *ghost_file_mutex;

/*
 * This constant is selected without any calculations. Just do not
 * want to pick up too big files with us in the image.
 */
#define MAX_GHOST_FILE_SIZE	(1 * 1024 * 1024)

static int open_remap_ghost(struct reg_file_info *rfi,
		RemapFilePathEntry *rfe)
{
	struct ghost_file *gf;
	GhostFileEntry *gfe = NULL;
	int gfd, ifd, ghost_flags;

	rfe->remap_id &= ~REMAP_GHOST;
	list_for_each_entry(gf, &ghost_files, list)
		if (gf->id == rfe->remap_id)
			goto gf_found;

	/*
	 * Ghost not found. We will create one in the same dir
	 * as the very first client of it thus resolving any
	 * issues with cross-device links.
	 */

	pr_info("Opening ghost file %#x for %s\n", rfe->remap_id, rfi->path);

	gf = shmalloc(sizeof(*gf));
	if (!gf)
		return -1;
	gf->remap.path = xmalloc(PATH_MAX);
	if (!gf->remap.path)
		goto err;

	ifd = open_image(CR_FD_GHOST_FILE, O_RSTR, rfe->remap_id);
	if (ifd < 0)
		goto err;

	if (pb_read_one(ifd, &gfe, PB_GHOST_FILE) < 0)
		goto close_ifd;

	/*
	 * For old formats where optional has_[dev|ino] is
	 * not present we will have zeros here which is quite
	 * a sign for "absent" fields.
	 */
	gf->dev = gfe->dev;
	gf->ino = gfe->ino;

	snprintf(gf->remap.path, PATH_MAX, "%s.cr.%x.ghost", rfi->path, rfe->remap_id);

	if (S_ISFIFO(gfe->mode)) {
		if (mknod(gf->remap.path, gfe->mode, 0)) {
			pr_perror("Can't create node for ghost file");
			goto close_ifd;
		}
		ghost_flags = O_RDWR; /* To not block */
	} else
		ghost_flags = O_WRONLY | O_CREAT | O_EXCL;

	gfd = open(gf->remap.path, ghost_flags, gfe->mode);
	if (gfd < 0) {
		pr_perror("Can't open ghost file %s", gf->remap.path);
		goto close_ifd;
	}

	if (fchown(gfd, gfe->uid, gfe->gid) < 0) {
		pr_perror("Can't reset user/group on ghost %#x", rfe->remap_id);
		goto close_all;
	}

	if (S_ISREG(gfe->mode)) {
		if (copy_file(ifd, gfd, 0) < 0)
			goto close_all;
	}

	ghost_file_entry__free_unpacked(gfe, NULL);
	close(ifd);
	close(gfd);

	gf->id = rfe->remap_id;
	gf->remap.users = 0;
	list_add_tail(&gf->list, &ghost_files);
gf_found:
	gf->remap.users++;
	rfi->remap = &gf->remap;
	return 0;

close_all:
	close_safe(&gfd);
close_ifd:
	close_safe(&ifd);
err:
	if (gfe)
		ghost_file_entry__free_unpacked(gfe, NULL);
	xfree(gf->remap.path);
	shfree_last(gf);
	return -1;
}

static int open_remap_linked(struct reg_file_info *rfi,
		RemapFilePathEntry *rfe)
{
	struct file_remap *rm;
	struct file_desc *rdesc;
	struct reg_file_info *rrfi;

	rdesc = find_file_desc_raw(FD_TYPES__REG, rfe->remap_id);
	if (!rdesc) {
		pr_err("Can't find target file %x\n", rfe->remap_id);
		return -1;
	}

	rm = xmalloc(sizeof(*rm));
	if (!rm)
		return -1;

	rrfi = container_of(rdesc, struct reg_file_info, d);
	pr_info("Remapped %s -> %s\n", rfi->path, rrfi->path);

	rm->path = rrfi->path;
	rm->users = 1;
	rfi->remap = rm;
	return 0;
}

static int collect_one_remap(void *obj, ProtobufCMessage *msg)
{
	int ret = -1;
	RemapFilePathEntry *rfe;
	struct file_desc *fdesc;
	struct reg_file_info *rfi;

	rfe = pb_msg(msg, RemapFilePathEntry);

	fdesc = find_file_desc_raw(FD_TYPES__REG, rfe->orig_id);
	if (fdesc == NULL) {
		pr_err("Remap for non existing file %#x\n",
				rfe->orig_id);
		goto out;
	}

	rfi = container_of(fdesc, struct reg_file_info, d);
	pr_info("Configuring remap %#x -> %#x\n", rfi->rfe->id, rfe->remap_id);

	if (rfe->remap_id & REMAP_GHOST)
		ret = open_remap_ghost(rfi, rfe);
	else
		ret = open_remap_linked(rfi, rfe);
out:
	return ret;
}

struct collect_image_info remap_cinfo = {
	.fd_type = CR_FD_REMAP_FPATH,
	.pb_type = PB_REMAP_FPATH,
	.collect = collect_one_remap,
};

static int dump_ghost_file(int _fd, u32 id, const struct stat *st)
{
	int img;
	GhostFileEntry gfe = GHOST_FILE_ENTRY__INIT;

	pr_info("Dumping ghost file contents (id %#x)\n", id);

	img = open_image(CR_FD_GHOST_FILE, O_DUMP, id);
	if (img < 0)
		return -1;

	gfe.uid = st->st_uid;
	gfe.gid = st->st_gid;
	gfe.mode = st->st_mode;

	gfe.has_dev = gfe.has_ino = true;
	gfe.dev = MKKDEV(MAJOR(st->st_dev), MINOR(st->st_dev));
	gfe.ino = st->st_ino;

	if (pb_write_one(img, &gfe, PB_GHOST_FILE))
		return -1;

	if (S_ISREG(st->st_mode)) {
		int fd, ret;
		char lpath[PSFDS];

		/*
		 * Reopen file locally since it may have no read
		 * permissions when drained
		 */
		sprintf(lpath, "/proc/self/fd/%d", _fd);
		fd = open(lpath, O_RDONLY);
		if (fd < 0) {
			pr_perror("Can't open ghost original file");
			return -1;
		}
		ret = copy_file(fd, img, st->st_size);
		close(fd);
		if (ret)
			return -1;
	}

	close(img);
	return 0;
}

void remap_put(struct file_remap *remap)
{
	mutex_lock(ghost_file_mutex);
	if (--remap->users == 0) {
		pr_info("Unlink the ghost %s\n", remap->path);
		unlink(remap->path);
	}
	mutex_unlock(ghost_file_mutex);
}

struct file_remap *lookup_ghost_remap(u32 dev, u32 ino)
{
	struct ghost_file *gf;

	mutex_lock(ghost_file_mutex);
	list_for_each_entry(gf, &ghost_files, list) {
		if (gf->dev == dev && gf->ino == ino) {
			gf->remap.users++;
			mutex_unlock(ghost_file_mutex);
			return &gf->remap;
		}
	}
	mutex_unlock(ghost_file_mutex);

	return NULL;
}

static int dump_ghost_remap(char *path, const struct stat *st, int lfd, u32 id)
{
	struct ghost_file *gf;
	RemapFilePathEntry rpe = REMAP_FILE_PATH_ENTRY__INIT;

	pr_info("Dumping ghost file for fd %d id %#x\n", lfd, id);

	if (st->st_size > MAX_GHOST_FILE_SIZE) {
		pr_err("Can't dump ghost file %s of %"PRIu64" size\n",
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
	BUG_ON(gf->id & REMAP_GHOST);

	rpe.orig_id = id;
	rpe.remap_id = gf->id | REMAP_GHOST;

	return pb_write_one(fdset_fd(glob_fdset, CR_FD_REMAP_FPATH),
			&rpe, PB_REMAP_FPATH);
}

static int create_link_remap(char *path, int len, int lfd, u32 *idp)
{
	char link_name[PATH_MAX], *tmp;
	RegFileEntry rfe = REG_FILE_ENTRY__INIT;
	FownEntry fwn = FOWN_ENTRY__INIT;

	if (!opts.link_remap_ok) {
		pr_err("Can't create link remap for %s. "
				"Use " LREMAP_PARAM " option.\n", path);
		return -1;
	}

	/*
	 * Linked remapping -- we create a hard link on a removed file
	 * in the directory original file used to sit.
	 *
	 * Bad news is than we can't easily open lfd's parent dir. Thus
	 * we have to just generate an absolute path and use it. The linkat
	 * will fail if we chose the bad one.
	 */

	link_name[0] = '.';
	memcpy(link_name + 1, path, len);
	tmp = link_name + len + 1;
	while (*tmp != '/') {
		BUG_ON(tmp == link_name);
		tmp--;
	}

	rfe.id = *idp 	= fd_id_generate_special();
	rfe.flags	= 0;
	rfe.pos		= 0;
	rfe.fown	= &fwn;
	rfe.name	= link_name + 1;

	/* Any 'unique' name works here actually. Remap works by reg-file ids. */
	sprintf(tmp + 1, "link_remap.%d", rfe.id);

	if (linkat(lfd, "", mntns_root, link_name, AT_EMPTY_PATH) < 0) {
		pr_perror("Can't link remap to %s", path);
		return -1;
	}

	return pb_write_one(fdset_fd(glob_fdset, CR_FD_REG_FILES), &rfe, PB_REG_FILE);
}

static int dump_linked_remap(char *path, int len, const struct stat *ost, int lfd, u32 id)
{
	u32 lid;
	RemapFilePathEntry rpe = REMAP_FILE_PATH_ENTRY__INIT;

	if (create_link_remap(path, len, lfd, &lid))
		return -1;

	rpe.orig_id = id;
	rpe.remap_id = lid;

	return pb_write_one(fdset_fd(glob_fdset, CR_FD_REMAP_FPATH),
			&rpe, PB_REMAP_FPATH);
}

static int check_path_remap(char *rpath, int plen, const struct stat *ost, int lfd, u32 id)
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
		return dump_ghost_remap(rpath + 1, ost, lfd, id);

	ret = fstatat(mntns_root, rpath, &pst, 0);
	if (ret < 0) {
		/*
		 * Linked file, but path is not accessible (unless any
		 * other error occurred). We can create a temporary link to it
		 * uning linkat with AT_EMPTY_PATH flag and remap it to this
		 * name.
		 */

		if (errno == ENOENT)
			return dump_linked_remap(rpath + 1, plen - 1, ost, lfd, id);

		pr_perror("Can't stat path");
		return -1;
	}

	if ((pst.st_ino != ost->st_ino) || (pst.st_dev != ost->st_dev)) {
		if (opts.evasive_devices &&
		    (S_ISCHR(ost->st_mode) || S_ISBLK(ost->st_mode)) &&
		    pst.st_rdev == ost->st_rdev)
			return 0;
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
	struct fd_link _link, *link;
	int rfd;

	RegFileEntry rfe = REG_FILE_ENTRY__INIT;

	if (!p->link) {
		if (fill_fdlink(lfd, p, &_link))
			return -1;
		link = &_link;
	} else
		link = p->link;

	pr_info("Dumping path for %d fd via self %d [%s]\n",
			p->fd, lfd, &link->name[1]);

	/*
	 * The regular path we can handle should start with slash.
	 */
	if (link->name[1] != '/') {
		pr_err("The path [%s] is not supported\n", &link->name[1]);
		return -1;
	}

	if (check_path_remap(link->name, link->len, &p->stat, lfd, id))
		return -1;

	rfe.id		= id;
	rfe.flags	= p->flags;
	rfe.pos		= p->pos;
	rfe.fown	= (FownEntry *)&p->fown;
	rfe.name	= &link->name[1];

	rfd = fdset_fd(glob_fdset, CR_FD_REG_FILES);

	return pb_write_one(rfd, &rfe, PB_REG_FILE);
}

const struct fdtype_ops regfile_dump_ops = {
	.type		= FD_TYPES__REG,
	.dump		= dump_one_reg_file,
};

static int open_path(struct file_desc *d,
		int(*open_cb)(struct reg_file_info *, void *), void *arg)
{
	struct reg_file_info *rfi;
	int tmp;

	rfi = container_of(d, struct reg_file_info, d);

	if (rfi->remap) {
		mutex_lock(ghost_file_mutex);
		if (link(rfi->remap->path, rfi->path) < 0) {
			pr_perror("Can't link %s -> %s",
					rfi->remap->path, rfi->path);
			return -1;
		}
	}

	tmp = open_cb(rfi, arg);
	if (tmp < 0) {
		pr_perror("Can't open file %s", rfi->path);
		return -1;
	}

	if (rfi->remap) {
		unlink(rfi->path);
		BUG_ON(!rfi->remap->users);
		if (--rfi->remap->users == 0) {
			pr_info("Unlink the ghost %s\n", rfi->remap->path);
			unlink(rfi->remap->path);
		}
		mutex_unlock(ghost_file_mutex);
	}

	if (restore_fown(tmp, rfi->rfe->fown))
		return -1;

	return tmp;
}

int open_path_by_id(u32 id, int (*open_cb)(struct reg_file_info *, void *), void *arg)
{
	struct file_desc *fd;

	fd = find_file_desc_raw(FD_TYPES__REG, id);
	if (fd == NULL) {
		pr_err("Can't find regfile for %#x\n", id);
		return -1;
	}

	return open_path(fd, open_cb, arg);
}

static int do_open_reg(struct reg_file_info *rfi, void *arg)
{
	int fd;

	fd = open(rfi->path, rfi->rfe->flags);
	if (fd < 0) {
		pr_perror("Can't open file %s on restore", rfi->path);
		return fd;
	}

	if ((rfi->rfe->pos != -1ULL) &&
			lseek(fd, rfi->rfe->pos, SEEK_SET) < 0) {
		pr_perror("Can't restore file pos");
		close(fd);
		return -1;
	}

	return fd;
}

static int open_fe_fd(struct file_desc *fd)
{
	return open_path(fd, do_open_reg, NULL);
}

int open_reg_by_id(u32 id)
{
	return open_path_by_id(id, do_open_reg, NULL);
}

static struct file_desc_ops reg_desc_ops = {
	.type = FD_TYPES__REG,
	.open = open_fe_fd,
};

static int collect_one_regfile(void *o, ProtobufCMessage *base)
{
	struct reg_file_info *rfi = o;

	rfi->rfe = pb_msg(base, RegFileEntry);
	rfi->path = rfi->rfe->name;
	rfi->remap = NULL;

	pr_info("Collected [%s] ID %#x\n", rfi->path, rfi->rfe->id);
	return file_desc_add(&rfi->d, rfi->rfe->id, &reg_desc_ops);
}

struct collect_image_info reg_file_cinfo = {
	.fd_type = CR_FD_REG_FILES,
	.pb_type = PB_REG_FILE,
	.priv_size = sizeof(struct reg_file_info),
	.collect = collect_one_regfile,
};

int prepare_shared_reg_files(void)
{
	ghost_file_mutex = shmalloc(sizeof(*ghost_file_mutex));
	if (!ghost_file_mutex)
		return -1;

	mutex_init(ghost_file_mutex);
	return 0;
}
