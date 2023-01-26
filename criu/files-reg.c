#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <ctype.h>
#include <sys/sendfile.h>
#include <sched.h>
#include <sys/capability.h>
#include <sys/ioctl.h>
#include <elf.h>
#include <linux/fiemap.h>
#include <linux/fs.h>

#include "tty.h"
#include "stats.h"

#ifndef SEEK_DATA
#define SEEK_DATA 3
#define SEEK_HOLE 4
#endif

/* Stolen from kernel/fs/nfs/unlink.c */
#define SILLYNAME_PREF	   ".nfs"
#define SILLYNAME_SUFF_LEN (((unsigned)sizeof(u64) << 1) + ((unsigned)sizeof(unsigned int) << 1))

/*
 * If the build-id exists, then it will most likely be present in the
 * beginning of the file. Therefore only the first 1MB will be mapped
 * and checked.
 */
#define BUILD_ID_MAP_SIZE 1048576
#define ST_UNIT		  512
#define EXTENT_MAX_COUNT  512

#include "cr_options.h"
#include "imgset.h"
#include "file-ids.h"
#include "mount.h"
#include "files.h"
#include "common/list.h"
#include "rst-malloc.h"
#include "fs-magic.h"
#include "namespaces.h"
#include "proc_parse.h"
#include "pstree.h"
#include "string.h"
#include "fault-injection.h"
#include "external.h"
#include "memfd.h"

#include "protobuf.h"
#include "util.h"
#include "images/regfile.pb-c.h"
#include "images/remap-file-path.pb-c.h"

#include "files-reg.h"
#include "plugin.h"
#include "string.h"

int setfsuid(uid_t fsuid);
int setfsgid(gid_t fsuid);

/*
 * Ghost files are those not visible from the FS. Dumping them is
 * nasty and the only way we have -- just carry its contents with
 * us. Any brave soul to implement link unlinked file back?
 */
struct ghost_file {
	struct list_head list;
	u32 id;

	u32 dev;
	u32 ino;

	struct file_remap remap;
};

static u32 ghost_file_ids = 1;
static LIST_HEAD(ghost_files);

/*
 * When opening remaps we first create a link on the remap
 * target, then open one, then unlink. In case the remap
 * source has more than one instance, these three steps
 * should be serialized with each other.
 */
static mutex_t *remap_open_lock;

static inline int init_remap_lock(void)
{
	remap_open_lock = shmalloc(sizeof(*remap_open_lock));
	if (!remap_open_lock)
		return -1;

	mutex_init(remap_open_lock);
	return 0;
}

static LIST_HEAD(remaps);

/*
 * Remember the name to delete it if needed on error or
 * rollback action. Note we don't expect that there will
 * be a HUGE number of link remaps, so in a sake of speed
 * we keep all data in memory.
 */
struct link_remap_rlb {
	struct list_head list;
	struct ns_id *mnt_ns;
	char *path;
};

static int note_link_remap(char *path, struct ns_id *nsid)
{
	struct link_remap_rlb *rlb;

	rlb = xmalloc(sizeof(*rlb));
	if (!rlb)
		goto err;

	rlb->path = xstrdup(path);
	if (!rlb->path)
		goto err2;

	rlb->mnt_ns = nsid;
	list_add(&rlb->list, &remaps);

	return 0;

err2:
	xfree(rlb);
err:
	pr_err("Can't note link remap for %s\n", path);
	return -1;
}

/* Trim "a/b/c/d" to "a/b/d" */
static int trim_last_parent(char *path)
{
	char *fname, *p;

	p = strrchr(path, '/');
	fname = p + 1;
	if (!p || *fname == '\0')
		return -1;

	while (p >= path && *p == '/')
		p--;

	if (p < path)
		return -1;

	while (p >= path && *p != '/')
		p--;
	p++;

	while (*fname != '\0')
		*p++ = *fname++;
	*p = '\0';

	return 0;
}

#define BUFSIZE (4096)

static int copy_chunk_from_file(int fd, int img, off_t off, size_t len)
{
	int ret;

	while (len > 0) {
		ret = sendfile(img, fd, &off, len);
		if (ret <= 0) {
			pr_perror("Can't send ghost to image");
			return -1;
		}

		len -= ret;
	}

	return 0;
}

static int copy_file_to_chunks(int fd, struct cr_img *img, size_t file_size)
{
	GhostChunkEntry ce = GHOST_CHUNK_ENTRY__INIT;
	off_t data, hole = 0;

	while (hole < file_size) {
		data = lseek(fd, hole, SEEK_DATA);
		if (data < 0) {
			if (errno == ENXIO)
				/* No data */
				break;
			else if (hole == 0) {
				/* No SEEK_HOLE/DATA by FS */
				data = 0;
				hole = file_size;
			} else {
				pr_perror("Can't seek file data");
				return -1;
			}
		} else {
			hole = lseek(fd, data, SEEK_HOLE);
			if (hole < 0) {
				pr_perror("Can't seek file hole");
				return -1;
			}
		}

		ce.len = hole - data;
		ce.off = data;

		if (pb_write_one(img, &ce, PB_GHOST_CHUNK))
			return -1;

		if (copy_chunk_from_file(fd, img_raw_fd(img), ce.off, ce.len))
			return -1;
	}

	return 0;
}

static int skip_outstanding(struct fiemap_extent *fe, size_t file_size)
{
	/* Skip outstanding extent */
	if (fe->fe_logical > file_size)
		return 1;

	/* Skip outstanding part of the extent */
	if (fe->fe_logical + fe->fe_length > file_size)
		fe->fe_length = file_size - fe->fe_logical;
	return 0;
}

static int copy_file_to_chunks_fiemap(int fd, struct cr_img *img, size_t file_size)
{
	GhostChunkEntry ce = GHOST_CHUNK_ENTRY__INIT;
	struct fiemap *fiemap_buf;
	struct fiemap_extent *ext_buf;
	int ext_buf_size, fie_buf_size;
	off_t pos = 0;
	unsigned int i;
	int ret = 0;
	int exit_code = 0;

	ext_buf_size = EXTENT_MAX_COUNT * sizeof(struct fiemap_extent);
	fie_buf_size = sizeof(struct fiemap) + ext_buf_size;

	fiemap_buf = xzalloc(fie_buf_size);
	if (!fiemap_buf) {
		pr_perror("Out of memory when allocating fiemap");
		return -1;
	}

	ext_buf = fiemap_buf->fm_extents;
	fiemap_buf->fm_length = FIEMAP_MAX_OFFSET;
	fiemap_buf->fm_flags |= FIEMAP_FLAG_SYNC;
	fiemap_buf->fm_extent_count = EXTENT_MAX_COUNT;

	do {
		fiemap_buf->fm_start = pos;
		memzero(ext_buf, ext_buf_size);
		ret = ioctl(fd, FS_IOC_FIEMAP, fiemap_buf);
		if (ret < 0) {
			if (errno == EOPNOTSUPP) {
				exit_code = -EOPNOTSUPP;
			} else {
				exit_code = -1;
				pr_perror("fiemap ioctl() failed");
			}
			goto out;
		} else if (fiemap_buf->fm_mapped_extents == 0) {
			goto out;
		}

		for (i = 0; i < fiemap_buf->fm_mapped_extents; i++) {
			if (skip_outstanding(&fiemap_buf->fm_extents[i], file_size))
				continue;

			ce.len = fiemap_buf->fm_extents[i].fe_length;
			ce.off = fiemap_buf->fm_extents[i].fe_logical;

			if (pb_write_one(img, &ce, PB_GHOST_CHUNK)) {
				exit_code = -1;
				goto out;
			}

			if (copy_chunk_from_file(fd, img_raw_fd(img), ce.off, ce.len)) {
				exit_code = -1;
				goto out;
			}

			if (fiemap_buf->fm_extents[i].fe_flags & FIEMAP_EXTENT_LAST) {
				/* there are no extents left, break. */
				goto out;
			}
		}

		/* Record file's logical offset as pos */
		pos = ce.len + ce.off;

		/* Since there are still extents left, continue. */
	} while (fiemap_buf->fm_mapped_extents == EXTENT_MAX_COUNT);
out:
	xfree(fiemap_buf);
	return exit_code;
}

static int copy_chunk_to_file(int img, int fd, off_t off, size_t len)
{
	int ret;

	while (len > 0) {
		if (lseek(fd, off, SEEK_SET) < 0) {
			pr_perror("Can't seek file");
			return -1;
		}

		if (opts.stream)
			ret = splice(img, NULL, fd, NULL, len, SPLICE_F_MOVE);
		else
			ret = sendfile(fd, img, NULL, len);
		if (ret < 0) {
			pr_perror("Can't send data");
			return -1;
		}

		off += ret;
		len -= ret;
	}

	return 0;
}

static int copy_file_from_chunks(struct cr_img *img, int fd, size_t file_size)
{
	if (ftruncate(fd, file_size) < 0) {
		pr_perror("Can't make file size");
		return -1;
	}

	while (1) {
		int ret;
		GhostChunkEntry *ce;

		ret = pb_read_one_eof(img, &ce, PB_GHOST_CHUNK);
		if (ret <= 0)
			return ret;

		if (copy_chunk_to_file(img_raw_fd(img), fd, ce->off, ce->len))
			return -1;

		ghost_chunk_entry__free_unpacked(ce, NULL);
	}
}

static int mkreg_ghost(char *path, GhostFileEntry *gfe, struct cr_img *img)
{
	int gfd, ret;

	gfd = open(path, O_WRONLY | O_CREAT | O_EXCL, gfe->mode);
	if (gfd < 0)
		return -1;

	if (gfe->chunks) {
		if (!gfe->has_size) {
			pr_err("Corrupted ghost image -> no size\n");
			close(gfd);
			return -1;
		}

		ret = copy_file_from_chunks(img, gfd, gfe->size);
	} else
		ret = copy_file(img_raw_fd(img), gfd, 0);
	if (ret < 0)
		unlink(path);
	close(gfd);

	return ret;
}

static int mklnk_ghost(char *path, GhostFileEntry *gfe)
{
	if (!gfe->symlnk_target) {
		pr_err("Ghost symlink target is NULL for %s. Image from old CRIU?\n", path);
		return -1;
	}

	if (symlink(gfe->symlnk_target, path) < 0) {
		/*
		 * ENOENT case is OK
		 * Take a look closer on create_ghost() function
		 */
		if (errno != ENOENT)
			pr_perror("symlink(%s, %s) failed", gfe->symlnk_target, path);
		return -1;
	}

	return 0;
}

static int ghost_apply_metadata(const char *path, GhostFileEntry *gfe)
{
	struct timeval tv[2];
	int ret = -1;

	if (S_ISLNK(gfe->mode)) {
		if (lchown(path, gfe->uid, gfe->gid) < 0) {
			pr_perror("Can't reset user/group on ghost %s", path);
			goto err;
		}

		/*
		 * We have no lchmod() function, and fchmod() will fail on
		 * O_PATH | O_NOFOLLOW fd. Yes, we have fchmodat()
		 * function and flag AT_SYMLINK_NOFOLLOW described in
		 * man 2 fchmodat, but it is not currently implemented. %)
		 */
	} else {
		if (chown(path, gfe->uid, gfe->gid) < 0) {
			pr_perror("Can't reset user/group on ghost %s", path);
			goto err;
		}

		if (chmod(path, gfe->mode)) {
			pr_perror("Can't set perms %o on ghost %s", gfe->mode, path);
			goto err;
		}
	}

	if (gfe->atim) {
		tv[0].tv_sec = gfe->atim->tv_sec;
		tv[0].tv_usec = gfe->atim->tv_usec;
		tv[1].tv_sec = gfe->mtim->tv_sec;
		tv[1].tv_usec = gfe->mtim->tv_usec;
		if (lutimes(path, tv)) {
			pr_perror("Can't set access and modification times on ghost %s", path);
			goto err;
		}
	}

	ret = 0;
err:
	return ret;
}

static int create_ghost_dentry(char *path, GhostFileEntry *gfe, struct cr_img *img)
{
	int ret = -1;
	char *msg;

again:
	if (S_ISFIFO(gfe->mode)) {
		if ((ret = mknod(path, gfe->mode, 0)) < 0)
			msg = "Can't create node for ghost file";
	} else if (S_ISCHR(gfe->mode) || S_ISBLK(gfe->mode)) {
		if (!gfe->has_rdev) {
			pr_err("No rdev for ghost device\n");
			goto err;
		}
		if ((ret = mknod(path, gfe->mode, gfe->rdev)) < 0)
			msg = "Can't create node for ghost dev";
	} else if (S_ISDIR(gfe->mode)) {
		if ((ret = mkdirpat(AT_FDCWD, path, gfe->mode)) < 0)
			msg = "Can't make ghost dir";
	} else if (S_ISLNK(gfe->mode)) {
		if ((ret = mklnk_ghost(path, gfe)) < 0)
			msg = "Can't create ghost symlink";
	} else {
		if ((ret = mkreg_ghost(path, gfe, img)) < 0)
			msg = "Can't create ghost regfile";
	}

	if (ret < 0) {
		/* Use grand parent, if parent directory does not exist */
		if (errno == ENOENT) {
			if (trim_last_parent(path) < 0) {
				pr_err("trim failed: @%s@\n", path);
				goto err;
			}
			goto again;
		}

		pr_perror("%s", msg);
		goto err;
	}

	ret = 0;
err:
	return ret;
}

static int nomntns_create_ghost(struct ghost_file *gf, GhostFileEntry *gfe, struct cr_img *img)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/%s", gf->remap.rpath);

	if (create_ghost_dentry(path, gfe, img))
		return -1;

	if (ghost_apply_metadata(path, gfe))
		return -1;

	__strlcpy(gf->remap.rpath, path + 1, PATH_MAX);
	pr_debug("Remap rpath is %s\n", gf->remap.rpath);
	return 0;
}

static int create_ghost(struct ghost_file *gf, GhostFileEntry *gfe, struct cr_img *img)
{
	struct mount_info *mi;
	char path[PATH_MAX], *rel_path, *rel_mp;

	if (!(root_ns_mask & CLONE_NEWNS))
		return nomntns_create_ghost(gf, gfe, img);

	mi = lookup_mnt_id(gf->remap.rmnt_id);
	if (!mi) {
		pr_err("The %d mount is not found for ghost\n", gf->remap.rmnt_id);
		return -1;
	}

	/* Get path relative to mountpoint from path relative to mntns */
	rel_path = get_relative_path(gf->remap.rpath, mi->ns_mountpoint);
	if (!rel_path) {
		pr_err("Can't get path %s relative to %s\n", gf->remap.rpath, mi->ns_mountpoint);
		return -1;
	}

	snprintf(path, sizeof(path), "%s%s%s", service_mountpoint(mi), rel_path[0] ? "/" : "", rel_path);
	pr_debug("Trying to create ghost on path %s\n", path);

	/* We get here while in service mntns */
	if (try_remount_writable(mi, false))
		return -1;

	if (create_ghost_dentry(path, gfe, img))
		return -1;

	if (ghost_apply_metadata(path, gfe))
		return -1;

	/*
	 * Convert the path back to mntns relative, as create_ghost_dentry
	 * might have changed it.
	 */
	rel_path = get_relative_path(path, service_mountpoint(mi));
	if (!rel_path) {
		pr_err("Can't get path %s relative to %s\n", path, service_mountpoint(mi));
		return -1;
	}

	rel_mp = get_relative_path(mi->ns_mountpoint, "/");
	if (!rel_mp) {
		pr_err("Can't get path %s relative to %s\n", mi->ns_mountpoint, "/");
		return -1;
	}

	snprintf(gf->remap.rpath, PATH_MAX, "%s%s%s", rel_mp, (rel_mp[0] && rel_path[0]) ? "/" : "", rel_path);
	pr_debug("Remap rpath is %s\n", gf->remap.rpath);
	return 0;
}

static inline void ghost_path(char *path, int plen, struct reg_file_info *rfi, RemapFilePathEntry *rpe)
{
	snprintf(path, plen, "%s.cr.%x.ghost", rfi->path, rpe->remap_id);
}

static int collect_remap_ghost(struct reg_file_info *rfi, RemapFilePathEntry *rpe)
{
	struct ghost_file *gf;

	list_for_each_entry(gf, &ghost_files, list)
		if (gf->id == rpe->remap_id)
			goto gf_found;

	/*
	 * Ghost not found. We will create one in the same dir
	 * as the very first client of it thus resolving any
	 * issues with cross-device links.
	 */

	pr_info("Opening ghost file %#x for %s\n", rpe->remap_id, rfi->path);

	gf = shmalloc(sizeof(*gf));
	if (!gf)
		return -1;

	/*
	 * The rpath is shmalloc-ed because we create the ghost
	 * file in root task context and generate its path there.
	 * However the path should be visible by the criu task
	 * in order to remove the ghost files from root FS (see
	 * try_clean_remaps()).
	 */
	gf->remap.rpath = shmalloc(PATH_MAX);
	if (!gf->remap.rpath)
		return -1;
	gf->remap.rpath[0] = 0;
	gf->id = rpe->remap_id;
	list_add_tail(&gf->list, &ghost_files);

gf_found:
	rfi->is_dir = gf->remap.is_dir;
	rfi->remap = &gf->remap;
	return 0;
}

static int open_remap_ghost(struct reg_file_info *rfi, RemapFilePathEntry *rpe)
{
	struct ghost_file *gf = container_of(rfi->remap, struct ghost_file, remap);
	GhostFileEntry *gfe = NULL;
	struct cr_img *img;

	if (rfi->remap->rpath[0])
		return 0;

	img = open_image(CR_FD_GHOST_FILE, O_RSTR, rpe->remap_id);
	if (!img)
		goto err;

	if (pb_read_one(img, &gfe, PB_GHOST_FILE) < 0)
		goto close_ifd;

	/*
	 * For old formats where optional has_[dev|ino] is
	 * not present we will have zeros here which is quite
	 * a sign for "absent" fields.
	 */
	gf->dev = gfe->dev;
	gf->ino = gfe->ino;
	gf->remap.rmnt_id = rfi->rfe->mnt_id;

	if (S_ISDIR(gfe->mode))
		__strlcpy(gf->remap.rpath, rfi->path, PATH_MAX);
	else
		ghost_path(gf->remap.rpath, PATH_MAX, rfi, rpe);

	if (create_ghost(gf, gfe, img))
		goto close_ifd;

	close_image(img);

	gf->remap.is_dir = S_ISDIR(gfe->mode);
	gf->remap.uid = gfe->uid;
	gf->remap.gid = gfe->gid;
	ghost_file_entry__free_unpacked(gfe, NULL);

	return 0;

close_ifd:
	close_image(img);
err:
	if (gfe)
		ghost_file_entry__free_unpacked(gfe, NULL);
	return -1;
}

static int collect_remap_linked(struct reg_file_info *rfi, RemapFilePathEntry *rpe)
{
	struct file_remap *rm;
	struct file_desc *rdesc;
	struct reg_file_info *rrfi;

	rdesc = find_file_desc_raw(FD_TYPES__REG, rpe->remap_id);
	if (!rdesc) {
		pr_err("Can't find target file %x\n", rpe->remap_id);
		return -1;
	}

	rm = xmalloc(sizeof(*rm));
	if (!rm)
		return -1;

	rrfi = container_of(rdesc, struct reg_file_info, d);
	pr_info("Remapped %s -> %s\n", rfi->path, rrfi->path);

	rm->rpath = rrfi->path;
	rm->is_dir = false;
	rm->uid = -1;
	rm->gid = -1;
	rm->rmnt_id = rfi->rfe->mnt_id;
	rfi->remap = rm;
	return 0;
}

static int open_remap_linked(struct reg_file_info *rfi)
{
	if (root_ns_mask & CLONE_NEWUSER) {
		int rfd;
		struct stat st;

		rfd = mntns_get_root_by_mnt_id(rfi->rfe->mnt_id);
		if (fstatat(rfd, rfi->remap->rpath, &st, AT_SYMLINK_NOFOLLOW)) {
			pr_perror("Can't get owner of link remap %s", rfi->remap->rpath);
			return -1;
		}

		rfi->remap->uid = st.st_uid;
		rfi->remap->gid = st.st_gid;
	}

	return 0;
}

static int collect_remap_dead_process(struct reg_file_info *rfi, RemapFilePathEntry *rfe)
{
	struct pstree_item *helper;

	helper = lookup_create_item(rfe->remap_id);
	if (!helper)
		return -1;

	if (helper->pid->state != TASK_UNDEF) {
		pr_info("Skipping helper for restoring /proc/%d; pid exists\n", rfe->remap_id);
		return 0;
	}

	helper->sid = root_item->sid;
	helper->pgid = root_item->pgid;
	helper->pid->ns[0].virt = rfe->remap_id;
	helper->parent = root_item;
	helper->ids = root_item->ids;
	if (init_pstree_helper(helper)) {
		pr_err("Can't init helper\n");
		return -1;
	}
	list_add_tail(&helper->sibling, &root_item->children);

	pr_info("Added a helper for restoring /proc/%d\n", vpid(helper));

	return 0;
}

struct remap_info {
	struct list_head list;
	RemapFilePathEntry *rpe;
	struct reg_file_info *rfi;
};

static int collect_one_remap(void *obj, ProtobufCMessage *msg, struct cr_img *i)
{
	struct remap_info *ri = obj;
	RemapFilePathEntry *rpe;
	struct file_desc *fdesc;

	ri->rpe = rpe = pb_msg(msg, RemapFilePathEntry);

	if (!rpe->has_remap_type) {
		rpe->has_remap_type = true;
		/* backward compatibility with images */
		if (rpe->remap_id & REMAP_GHOST) {
			rpe->remap_id &= ~REMAP_GHOST;
			rpe->remap_type = REMAP_TYPE__GHOST;
		} else
			rpe->remap_type = REMAP_TYPE__LINKED;
	}

	fdesc = find_file_desc_raw(FD_TYPES__REG, rpe->orig_id);
	if (fdesc == NULL) {
		pr_err("Remap for non existing file %#x\n", rpe->orig_id);
		return -1;
	}

	ri->rfi = container_of(fdesc, struct reg_file_info, d);

	switch (rpe->remap_type) {
	case REMAP_TYPE__GHOST:
		if (collect_remap_ghost(ri->rfi, ri->rpe))
			return -1;
		break;
	case REMAP_TYPE__LINKED:
		if (collect_remap_linked(ri->rfi, ri->rpe))
			return -1;
		break;
	case REMAP_TYPE__PROCFS:
		if (collect_remap_dead_process(ri->rfi, rpe) < 0)
			return -1;
		break;
	default:
		break;
	}

	list_add_tail(&ri->list, &remaps);

	return 0;
}

static int prepare_one_remap(struct remap_info *ri)
{
	int ret = -1;
	RemapFilePathEntry *rpe = ri->rpe;
	struct reg_file_info *rfi = ri->rfi;

	pr_info("Configuring remap %#x -> %#x\n", rfi->rfe->id, rpe->remap_id);

	switch (rpe->remap_type) {
	case REMAP_TYPE__LINKED:
		ret = open_remap_linked(rfi);
		break;
	case REMAP_TYPE__GHOST:
		ret = open_remap_ghost(rfi, rpe);
		break;
	case REMAP_TYPE__PROCFS:
		/* handled earlier by collect_remap_dead_process */
		ret = 0;
		break;
	default:
		pr_err("unknown remap type %u\n", rpe->remap_type);
		goto out;
	}

out:
	return ret;
}

int prepare_remaps(void)
{
	struct remap_info *ri;
	int ret = 0;

	ret = init_remap_lock();
	if (ret)
		return ret;

	list_for_each_entry(ri, &remaps, list) {
		ret = prepare_one_remap(ri);
		if (ret)
			break;
	}

	return ret;
}

static int clean_one_remap(struct remap_info *ri)
{
	struct file_remap *remap = ri->rfi->remap;
	int mnt_id, ret;
	struct mount_info *mi;
	char path[PATH_MAX], *rel_path;

	if (remap->rpath[0] == 0)
		return 0;

	if (!(root_ns_mask & CLONE_NEWNS)) {
		snprintf(path, sizeof(path), "/%s", remap->rpath);
		goto nomntns;
	}

	mnt_id = ri->rfi->rfe->mnt_id; /* rirfirfe %) */
	mi = lookup_mnt_id(mnt_id);
	if (!mi) {
		pr_err("The %d mount is not found for ghost\n", mnt_id);
		return -1;
	}

	rel_path = get_relative_path(remap->rpath, mi->ns_mountpoint);
	if (!rel_path) {
		pr_err("Can't get path %s relative to %s\n", remap->rpath, mi->ns_mountpoint);
		return -1;
	}

	snprintf(path, sizeof(path), "%s%s%s", service_mountpoint(mi), strlen(rel_path) ? "/" : "", rel_path);

	/* We get here while in service mntns */
	if (try_remount_writable(mi, false))
		return -1;

nomntns:
	pr_info("Unlink remap %s\n", path);

	if (remap->is_dir)
		ret = rmdir(path);
	else
		ret = unlink(path);

	if (ret) {
		pr_perror("Couldn't unlink remap %s", path);
		return -1;
	}

	remap->rpath[0] = 0;

	return 0;
}

int try_clean_remaps(bool only_ghosts)
{
	struct remap_info *ri;
	int ret = 0;

	list_for_each_entry(ri, &remaps, list) {
		if (ri->rpe->remap_type == REMAP_TYPE__GHOST)
			ret |= clean_one_remap(ri);
		else if (only_ghosts)
			continue;
		else if (ri->rpe->remap_type == REMAP_TYPE__LINKED)
			ret |= clean_one_remap(ri);
	}

	return ret;
}

static struct collect_image_info remap_cinfo = {
	.fd_type = CR_FD_REMAP_FPATH,
	.pb_type = PB_REMAP_FPATH,
	.priv_size = sizeof(struct remap_info),
	.collect = collect_one_remap,
};

/* Tiny files don't need to generate chunks in ghost image. */
#define GHOST_CHUNKS_THRESH (3 * 4096)

static int dump_ghost_file(int _fd, u32 id, const struct stat *st, dev_t phys_dev)
{
	struct cr_img *img;
	int exit_code = -1;
	GhostFileEntry gfe = GHOST_FILE_ENTRY__INIT;
	Timeval atim = TIMEVAL__INIT, mtim = TIMEVAL__INIT;
	char pathbuf[PATH_MAX];

	pr_info("Dumping ghost file contents (id %#x)\n", id);

	img = open_image(CR_FD_GHOST_FILE, O_DUMP, id);
	if (!img)
		return -1;

	gfe.uid = userns_uid(st->st_uid);
	gfe.gid = userns_gid(st->st_gid);
	gfe.mode = st->st_mode;

	gfe.atim = &atim;
	gfe.mtim = &mtim;
	gfe.atim->tv_sec = st->st_atim.tv_sec;
	gfe.atim->tv_usec = st->st_atim.tv_nsec / 1000;
	gfe.mtim->tv_sec = st->st_mtim.tv_sec;
	gfe.mtim->tv_usec = st->st_mtim.tv_nsec / 1000;

	gfe.has_dev = gfe.has_ino = true;
	gfe.dev = phys_dev;
	gfe.ino = st->st_ino;

	if (S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode)) {
		gfe.has_rdev = true;
		gfe.rdev = st->st_rdev;
	}

	if (S_ISREG(st->st_mode) && (st->st_size >= GHOST_CHUNKS_THRESH)) {
		gfe.has_chunks = gfe.chunks = true;
		gfe.has_size = true;
		gfe.size = st->st_size;
	}

	/*
	 * We set gfe.symlnk_target only if we need to dump
	 * symlink content, otherwise we leave it NULL.
	 * It will be taken into account on restore in mklnk_ghost function.
	 */
	if (S_ISLNK(st->st_mode)) {
		ssize_t ret;

		/*
		 * We assume that _fd opened with O_PATH | O_NOFOLLOW
		 * flags because S_ISLNK(st->st_mode). With current kernel version,
		 * it's looks like correct assumption in any case.
		 */
		ret = readlinkat(_fd, "", pathbuf, sizeof(pathbuf) - 1);
		if (ret < 0) {
			pr_perror("Can't readlinkat");
			goto err_out;
		}

		pathbuf[ret] = 0;

		if (ret != st->st_size) {
			pr_err("Buffer for readlinkat is too small: ret %zd, st_size %" PRId64 ", buf %u %s\n", ret,
			       st->st_size, PATH_MAX, pathbuf);
			goto err_out;
		}

		gfe.symlnk_target = pathbuf;
	}

	if (pb_write_one(img, &gfe, PB_GHOST_FILE))
		goto err_out;

	if (S_ISREG(st->st_mode)) {
		int fd, ret;

		/*
		 * Reopen file locally since it may have no read
		 * permissions when drained
		 */
		fd = open_proc(PROC_SELF, "fd/%d", _fd);
		if (fd < 0) {
			pr_perror("Can't open ghost original file");
			goto err_out;
		}

		if (gfe.chunks) {
			if (opts.ghost_fiemap) {
				ret = copy_file_to_chunks_fiemap(fd, img, st->st_size);
				if (ret == -EOPNOTSUPP) {
					pr_debug("file system don't support fiemap\n");
					ret = copy_file_to_chunks(fd, img, st->st_size);
				}
			} else {
				ret = copy_file_to_chunks(fd, img, st->st_size);
			}
		} else {
			ret = copy_file(fd, img_raw_fd(img), st->st_size);
		}

		close(fd);
		if (ret)
			goto err_out;
	}

	exit_code = 0;
err_out:
	close_image(img);
	return exit_code;
}

struct file_remap *lookup_ghost_remap(u32 dev, u32 ino)
{
	struct ghost_file *gf;

	list_for_each_entry(gf, &ghost_files, list) {
		if (gf->ino == ino && (gf->dev == dev)) {
			return &gf->remap;
		}
	}

	return NULL;
}

static int dump_ghost_remap(char *path, const struct stat *st, int lfd, u32 id, struct ns_id *nsid)
{
	struct ghost_file *gf;
	RemapFilePathEntry rpe = REMAP_FILE_PATH_ENTRY__INIT;
	dev_t phys_dev;

	pr_info("Dumping ghost file for fd %d id %#x\n", lfd, id);

	if (st->st_blocks * ST_UNIT > opts.ghost_limit) {
		pr_err("Can't dump ghost file %s of %" PRIu64 " size, increase limit\n", path, st->st_blocks * ST_UNIT);
		return -1;
	}

	phys_dev = phys_stat_resolve_dev(nsid, st->st_dev, path);
	list_for_each_entry(gf, &ghost_files, list)
		if ((gf->dev == phys_dev) && (gf->ino == st->st_ino))
			goto dump_entry;

	gf = xmalloc(sizeof(*gf));
	if (gf == NULL)
		return -1;

	gf->dev = phys_dev;
	gf->ino = st->st_ino;
	gf->id = ghost_file_ids++;

	if (dump_ghost_file(lfd, gf->id, st, phys_dev)) {
		xfree(gf);
		return -1;
	}

	list_add_tail(&gf->list, &ghost_files);

dump_entry:
	rpe.orig_id = id;
	rpe.remap_id = gf->id;
	rpe.has_remap_type = true;
	rpe.remap_type = REMAP_TYPE__GHOST;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_REMAP_FPATH), &rpe, PB_REMAP_FPATH);
}

static void __rollback_link_remaps(bool do_unlink)
{
	struct link_remap_rlb *rlb, *tmp;
	int mntns_root;

	list_for_each_entry_safe(rlb, tmp, &remaps, list) {
		if (do_unlink) {
			mntns_root = mntns_get_root_fd(rlb->mnt_ns);
			if (mntns_root >= 0)
				unlinkat(mntns_root, rlb->path, 0);
			else
				pr_err("Failed to clenaup %s link remap\n", rlb->path);
		}

		list_del(&rlb->list);
		xfree(rlb->path);
		xfree(rlb);
	}
}

void delete_link_remaps(void)
{
	__rollback_link_remaps(true);
}
void free_link_remaps(void)
{
	__rollback_link_remaps(false);
}
static int linkat_hard(int odir, char *opath, int ndir, char *npath, uid_t uid, gid_t gid, int flags);

static void check_overlayfs_fallback(char *path, const struct fd_parms *parms, bool *fallback)
{
	if (!fallback || parms->fs_type != OVERLAYFS_SUPER_MAGIC)
		return;

	/*
	 * In overlayFS, linkat() fails with ENOENT if the removed file is
	 * originated from lower layer. The cause of failure is that linkat()
	 * sees the file has st_nlink=0, which is different than st_nlink=1 we
	 * got from earlier fstat() on lfd. By setting *fb=true, we will fall
	 * back to dump_ghost_remap() as it is what should have been done to
	 * removed files with st_nlink=0.
	 */
	pr_info("Unable to link-remap %s on overlayFS, fall back to dump_ghost_remap\n", path);
	*fallback = true;
}

static int create_link_remap(char *path, int len, int lfd, u32 *idp, struct ns_id *nsid, const struct fd_parms *parms,
			     bool *fallback)
{
	char link_name[PATH_MAX], *tmp;
	FileEntry fe = FILE_ENTRY__INIT;
	RegFileEntry rfe = REG_FILE_ENTRY__INIT;
	FownEntry fwn = FOWN_ENTRY__INIT;
	int mntns_root;
	const struct stat *ost = &parms->stat;

	if (!opts.link_remap_ok) {
		pr_err("Can't create link remap for %s. "
		       "Use " LREMAP_PARAM " option.\n",
		       path);
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
	tmp = link_name + len;
	while (*tmp != '/') {
		BUG_ON(tmp == link_name);
		tmp--;
	}

	fd_id_generate_special(NULL, idp);
	rfe.id = *idp;
	rfe.flags = 0;
	rfe.pos = 0;
	rfe.fown = &fwn;
	rfe.name = link_name + 1;

	/* Any 'unique' name works here actually. Remap works by reg-file ids. */
	snprintf(tmp + 1, sizeof(link_name) - (size_t)(tmp - link_name - 1), "link_remap.%d", rfe.id);

	mntns_root = mntns_get_root_fd(nsid);

	while (linkat_hard(lfd, "", mntns_root, link_name, ost->st_uid, ost->st_gid, AT_EMPTY_PATH) < 0) {
		if (errno != ENOENT) {
			pr_perror("Can't link remap to %s", path);
			return -1;
		}

		/* Use grand parent, if parent directory does not exist. */
		if (trim_last_parent(link_name) < 0) {
			pr_err("trim failed: @%s@\n", link_name);
			check_overlayfs_fallback(path, parms, fallback);
			return -1;
		}
	}

	if (note_link_remap(link_name, nsid))
		return -1;

	fe.type = FD_TYPES__REG;
	fe.id = rfe.id;
	fe.reg = &rfe;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);
}

static int dump_linked_remap(char *path, int len, const struct fd_parms *parms, int lfd, u32 id, struct ns_id *nsid,
			     bool *fallback)
{
	u32 lid;
	RemapFilePathEntry rpe = REMAP_FILE_PATH_ENTRY__INIT;

	if (create_link_remap(path, len, lfd, &lid, nsid, parms, fallback))
		return -1;

	rpe.orig_id = id;
	rpe.remap_id = lid;
	rpe.has_remap_type = true;
	rpe.remap_type = REMAP_TYPE__LINKED;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_REMAP_FPATH), &rpe, PB_REMAP_FPATH);
}

static pid_t *dead_pids;
static int n_dead_pids;

int dead_pid_conflict(void)
{
	int i;

	for (i = 0; i < n_dead_pids; i++) {
		struct pid *node;
		pid_t pid = dead_pids[i];

		node = pstree_pid_by_virt(pid);
		if (!node)
			continue;

		/* Main thread */
		if (node->state != TASK_THREAD)
			continue;

		pr_err("Conflict with a dead task with the same PID as of this thread (virt %d, real %d).\n",
		       node->ns[0].virt, node->real);
		return -1;
	}

	return 0;
}

static int have_seen_dead_pid(pid_t pid)
{
	int i;

	for (i = 0; i < n_dead_pids; i++) {
		if (dead_pids[i] == pid)
			return 1;
	}

	if (xrealloc_safe(&dead_pids, sizeof(*dead_pids) * (n_dead_pids + 1)))
		return -1;
	dead_pids[n_dead_pids++] = pid;

	return 0;
}

static int dump_dead_process_remap(pid_t pid, u32 id)
{
	RemapFilePathEntry rpe = REMAP_FILE_PATH_ENTRY__INIT;
	int ret;

	ret = have_seen_dead_pid(pid);
	if (ret < 0)
		return -1;
	if (ret) {
		pr_info("Found dead pid %d already, skipping remap\n", pid);
		return 0;
	}

	rpe.orig_id = id;
	rpe.remap_id = pid;
	rpe.has_remap_type = true;
	rpe.remap_type = REMAP_TYPE__PROCFS;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_REMAP_FPATH), &rpe, PB_REMAP_FPATH);
}

static bool is_sillyrename_name(char *name)
{
	int i;

	name = strrchr(name, '/');
	BUG_ON(name == NULL); /* see check in dump_one_reg_file */
	name++;

	/*
	 * Strictly speaking this check is not bullet-proof. User
	 * can create file with this name by hands and we have no
	 * API to distinguish really-silly-renamed files from those
	 * fake names :(
	 *
	 * But since NFS people expect .nfsXXX files to be unstable,
	 * we treat them as such too.
	 */

	if (strncmp(name, SILLYNAME_PREF, sizeof(SILLYNAME_PREF) - 1))
		return false;

	name += sizeof(SILLYNAME_PREF) - 1;
	for (i = 0; i < SILLYNAME_SUFF_LEN; i++)
		if (!isxdigit(name[i]))
			return false;

	return true;
}

static inline bool nfs_silly_rename(char *rpath, const struct fd_parms *parms)
{
	return (parms->fs_type == NFS_SUPER_MAGIC) && is_sillyrename_name(rpath);
}

static int check_path_remap(struct fd_link *link, const struct fd_parms *parms, int lfd, u32 id, struct ns_id *nsid)
{
	char *rpath = link->name;
	int plen = link->len;
	int ret, mntns_root;
	struct stat pst;
	const struct stat *ost = &parms->stat;
	int flags = 0;
	bool fallback = false;

	if (parms->fs_type == PROC_SUPER_MAGIC) {
		/* The file points to /proc/pid/<foo> where pid is a dead
		 * process. We remap this file by adding this pid to be
		 * fork()ed into a TASK_HELPER state so that we can point to it
		 * on restore.
		 */
		pid_t pid;
		char *start, *end;

		/* skip "./proc/" */
		start = strstr(rpath, "/");
		if (!start)
			return -1;
		start = strstr(start + 1, "/");
		if (!start) /* it's /proc */
			return 0;
		pid = strtol(start + 1, &end, 10);

		/* If strtol didn't convert anything, then we are looking at
		 * something like /proc/kmsg, which we shouldn't mess with.
		 * Anything under /proc/<pid> (including that directory itself)
		 * can be c/r'd with a dead pid remap, so let's allow all such
		 * cases.
		 */
		if (pid != 0) {
			bool is_dead = link_strip_deleted(link);
			mntns_root = mntns_get_root_fd(nsid);
			if (mntns_root < 0)
				return -1;

			/* /proc/<pid> will be "/proc/1 (deleted)" when it is
			 * dead, but a path like /proc/1/mountinfo won't have
			 * the suffix, since it isn't actually deleted (still
			 * exists, but the parent dir is deleted). So, if we
			 * have a path like /proc/1/mountinfo, test if /proc/1
			 * exists instead, since this is what CRIU will need to
			 * open on restore.
			 */
			if (!is_dead) {
				*end = 0;
				is_dead = faccessat(mntns_root, rpath, F_OK, 0);
				*end = '/';
			}

			if (is_dead) {
				pr_info("Dumping dead process remap of %d\n", pid);
				return dump_dead_process_remap(pid, id);
			}
		}

		return 0;
	} else if (parms->fs_type == DEVPTS_SUPER_MAGIC) {
		/*
		 * It's safe to call stripping here because
		 * file paths are having predefined format for
		 * this FS and can't have a valid " (deleted)"
		 * postfix as a part of not deleted filename.
		 */
		link_strip_deleted(link);
		/*
		 * Devpts devices/files are generated by the
		 * kernel itself so we should not try to generate
		 * any kind of ghost files here even if file is
		 * no longer exist.
		 */
		return 0;
	}

	if (ost->st_nlink == 0) {
		/*
		 * Unpleasant, but easy case. File is completely invisible
		 * from the FS. Just dump its contents and that's it. But
		 * be careful whether anybody still has any of its hardlinks
		 * also open.
		 */
		link_strip_deleted(link);
		return dump_ghost_remap(rpath + 1, ost, lfd, id, nsid);
	}

	if (nfs_silly_rename(rpath, parms)) {
		/*
		 * If this is NFS silly-rename file the path we have at hands
		 * will be accessible by fstat(), but once we kill the dumping
		 * tasks it will disappear. So we just go ahead an dump it as
		 * linked-remap file (NFS will allow us to create more hard
		 * links on it) to have some persistent name at hands.
		 */
		pr_debug("Dump silly-rename linked remap for %x\n", id);
		return dump_linked_remap(rpath + 1, plen - 1, parms, lfd, id, nsid, NULL);
	}

	mntns_root = mntns_get_root_fd(nsid);
	if (mntns_root < 0)
		return -1;

	if (S_ISLNK(parms->stat.st_mode))
		flags = AT_SYMLINK_NOFOLLOW;

	ret = fstatat(mntns_root, rpath, &pst, flags);
	if (ret < 0) {
		/*
		 * Linked file, but path is not accessible (unless any
		 * other error occurred). We can create a temporary link to it
		 * using linkat with AT_EMPTY_PATH flag and remap it to this
		 * name.
		 */

		if (errno == ENOENT) {
			link_strip_deleted(link);
			ret = dump_linked_remap(rpath + 1, plen - 1, parms, lfd, id, nsid, &fallback);
			if (ret < 0 && fallback) {
				/* fallback is true only if following conditions are true:
				 * 1. linkat() inside dump_linked_remap() failed with ENOENT
				 * 2. parms->fs_type == overlayFS
				 */
				return dump_ghost_remap(rpath + 1, ost, lfd, id, nsid);
			}
			return ret;
		}

		pr_perror("Can't stat path");
		return -1;
	}

	if ((pst.st_ino != ost->st_ino) || (pst.st_dev != ost->st_dev)) {
		if (opts.evasive_devices && (S_ISCHR(ost->st_mode) || S_ISBLK(ost->st_mode)) &&
		    pst.st_rdev == ost->st_rdev)
			return 0;
		/*
		 * FIXME linked file, but the name we see it by is reused
		 * by somebody else. We can dump it with linked remaps, but
		 * we'll have difficulties on restore -- we will have to
		 * move the existing file aside, then restore this one,
		 * unlink, then move the original file back. It's fairly
		 * easy to do, but we don't do it now, since unlinked files
		 * have the "(deleted)" suffix in proc and name conflict
		 * is unlikely :)
		 */
		pr_err("Unaccessible path opened %u:%u, need %u:%u\n", (int)pst.st_dev, (int)pst.st_ino,
		       (int)ost->st_dev, (int)ost->st_ino);
		return -1;
	}

	/*
	 * File is linked and visible by the name it is opened by
	 * this task. Go ahead and dump it.
	 */
	return 0;
}

static bool should_check_size(int flags)
{
	/* Skip size if file has O_APPEND and O_WRONLY flags (e.g. log file). */
	if (((flags & O_ACCMODE) == O_WRONLY) && (flags & O_APPEND))
		return false;

	return true;
}

/*
 * Gets the build-id (If it exists) from 32-bit ELF files.
 * Returns the number of bytes of the build-id if it could
 * be obtained, else -1.
 */
static int get_build_id_32(Elf32_Ehdr *file_header, unsigned char **build_id, const int fd, size_t mapped_size)
{
	int size, num_iterations;
	size_t file_header_end;
	Elf32_Phdr *program_header, *program_header_end;
	Elf32_Nhdr *note_header_end, *note_header = NULL;

	file_header_end = (size_t)file_header + mapped_size;
	if (sizeof(Elf32_Ehdr) > mapped_size)
		return -1;

	/*
	 * If the file doesn't have at least 1 program header entry, it definitely can't
	 * have a build-id.
	 */
	if (!file_header->e_phnum) {
		pr_warn("Couldn't find any program headers for file with fd %d\n", fd);
		return -1;
	}

	program_header = (Elf32_Phdr *)(file_header->e_phoff + (char *)file_header);
	if (program_header <= (Elf32_Phdr *)file_header)
		return -1;

	program_header_end = (Elf32_Phdr *)(file_header_end - sizeof(Elf32_Phdr));

	/*
	 * If the file has a build-id, it will be in the PT_NOTE program header
	 * entry AKA the note sections.
	 */
	for (num_iterations = 0; num_iterations < file_header->e_phnum; num_iterations++, program_header++) {
		if (program_header > program_header_end)
			break;
		if (program_header->p_type != PT_NOTE)
			continue;

		note_header = (Elf32_Nhdr *)(program_header->p_offset + (char *)file_header);
		if (note_header <= (Elf32_Nhdr *)file_header) {
			note_header = NULL;
			continue;
		}

		note_header_end = (Elf32_Nhdr *)min_t(char *, (char *)note_header + program_header->p_filesz,
						      (char *)(file_header_end - sizeof(Elf32_Nhdr)));

		/* The note type for the build-id is NT_GNU_BUILD_ID. */
		while (note_header <= note_header_end && note_header->n_type != NT_GNU_BUILD_ID)
			note_header = (Elf32_Nhdr *)((char *)note_header + sizeof(Elf32_Nhdr) +
						     ALIGN(note_header->n_namesz, 4) + ALIGN(note_header->n_descsz, 4));

		if (note_header > note_header_end) {
			note_header = NULL;
			continue;
		}
		break;
	}

	if (!note_header) {
		pr_debug("Couldn't find the build-id note for file with fd %d\n", fd);
		return -1;
	}

	/*
	 * If the size of the notes description is too large or is invalid
	 * then the build-id could not be obtained.
	 */
	if (note_header->n_descsz <= 0 || note_header->n_descsz > 512) {
		pr_warn("Invalid description size for build-id note for file with fd %d\n", fd);
		return -1;
	}

	size = note_header->n_descsz;
	note_header = (Elf32_Nhdr *)((char *)note_header + sizeof(Elf32_Nhdr) + ALIGN(note_header->n_namesz, 4));
	note_header_end = (Elf32_Nhdr *)(file_header_end - size);
	if (note_header <= (Elf32_Nhdr *)file_header || note_header > note_header_end)
		return -1;

	*build_id = (unsigned char *)xmalloc(size);
	if (!*build_id)
		return -1;

	memcpy(*build_id, (void *)note_header, size);
	return size;
}

/*
 * Gets the build-id (If it exists) from 64-bit ELF files.
 * Returns the number of bytes of the build-id if it could
 * be obtained, else -1.
 */
static int get_build_id_64(Elf64_Ehdr *file_header, unsigned char **build_id, const int fd, size_t mapped_size)
{
	int size, num_iterations;
	size_t file_header_end;
	Elf64_Phdr *program_header, *program_header_end;
	Elf64_Nhdr *note_header_end, *note_header = NULL;

	file_header_end = (size_t)file_header + mapped_size;
	if (sizeof(Elf64_Ehdr) > mapped_size)
		return -1;

	/*
	 * If the file doesn't have at least 1 program header entry, it definitely can't
	 * have a build-id.
	 */
	if (!file_header->e_phnum) {
		pr_warn("Couldn't find any program headers for file with fd %d\n", fd);
		return -1;
	}

	program_header = (Elf64_Phdr *)(file_header->e_phoff + (char *)file_header);
	if (program_header <= (Elf64_Phdr *)file_header)
		return -1;

	program_header_end = (Elf64_Phdr *)(file_header_end - sizeof(Elf64_Phdr));

	/*
	 * If the file has a build-id, it will be in the PT_NOTE program header
	 * entry AKA the note sections.
	 */
	for (num_iterations = 0; num_iterations < file_header->e_phnum; num_iterations++, program_header++) {
		if (program_header > program_header_end)
			break;
		if (program_header->p_type != PT_NOTE)
			continue;

		note_header = (Elf64_Nhdr *)(program_header->p_offset + (char *)file_header);
		if (note_header <= (Elf64_Nhdr *)file_header) {
			note_header = NULL;
			continue;
		}

		note_header_end = (Elf64_Nhdr *)min_t(char *, (char *)note_header + program_header->p_filesz,
						      (char *)(file_header_end - sizeof(Elf64_Nhdr)));

		/* The note type for the build-id is NT_GNU_BUILD_ID. */
		while (note_header <= note_header_end && note_header->n_type != NT_GNU_BUILD_ID)
			note_header = (Elf64_Nhdr *)((char *)note_header + sizeof(Elf64_Nhdr) +
						     ALIGN(note_header->n_namesz, 4) + ALIGN(note_header->n_descsz, 4));

		if (note_header > note_header_end) {
			note_header = NULL;
			continue;
		}
		break;
	}

	if (!note_header) {
		pr_debug("Couldn't find the build-id note for file with fd %d\n", fd);
		return -1;
	}

	/*
	 * If the size of the notes description is too large or is invalid
	 * then the build-id could not be obtained.
	 */
	if (note_header->n_descsz <= 0 || note_header->n_descsz > 512) {
		pr_warn("Invalid description size for build-id note for file with fd %d\n", fd);
		return -1;
	}

	size = note_header->n_descsz;
	note_header = (Elf64_Nhdr *)((char *)note_header + sizeof(Elf64_Nhdr) + ALIGN(note_header->n_namesz, 4));
	note_header_end = (Elf64_Nhdr *)(file_header_end - size);
	if (note_header <= (Elf64_Nhdr *)file_header || note_header > note_header_end)
		return -1;

	*build_id = (unsigned char *)xmalloc(size);
	if (!*build_id)
		return -1;

	memcpy(*build_id, (void *)note_header, size);
	return size;
}

/*
 * Finds the build-id of the file by checking if the file is an ELF file
 * and then calling either the 32-bit or the 64-bit function as necessary.
 * Returns the number of bytes of the build-id if it could be
 * obtained, else -1.
 */
static int get_build_id(const int fd, const struct stat *fd_status, unsigned char **build_id)
{
	char buf[SELFMAG + 1];
	void *start_addr;
	size_t mapped_size;
	int ret = -1;

	if (read(fd, buf, SELFMAG + 1) != SELFMAG + 1)
		return -1;

	/*
	 * The first 4 bytes contain a magic number identifying the file as an
	 * ELF file. They should contain the characters ‘\x7f’, ‘E’, ‘L’, and
	 * ‘F’, respectively. These characters are together defined as ELFMAG.
	 */
	if (strncmp(buf, ELFMAG, SELFMAG))
		return -1;

	/*
	 * If the build-id exists, then it will most likely be present in the
	 * beginning of the file. Therefore at most only the first 1 MB of the
	 * file is mapped.
	 */
	mapped_size = min_t(size_t, fd_status->st_size, BUILD_ID_MAP_SIZE);
	start_addr = mmap(0, mapped_size, PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (start_addr == MAP_FAILED) {
		pr_warn("Couldn't mmap file with fd %d\n", fd);
		return -1;
	}

	if (buf[EI_CLASS] == ELFCLASS32)
		ret = get_build_id_32(start_addr, build_id, fd, mapped_size);
	if (buf[EI_CLASS] == ELFCLASS64)
		ret = get_build_id_64(start_addr, build_id, fd, mapped_size);

	munmap(start_addr, mapped_size);
	return ret;
}

/*
 * Finds and stores the build-id of a file, if it exists, so that it can be validated
 * while restoring.
 * Returns 1 if the build-id of the file could be stored, -1 if there was an error
 * or 0 if the build-id could not be obtained.
 */
static int store_validation_data_build_id(RegFileEntry *rfe, int lfd, const struct fd_parms *p)
{
	unsigned char *build_id = NULL;
	int build_id_size, allocated_size;
	int fd;

	/*
	 * Checks whether the file is at least big enough to try and read the first
	 * four (SELFMAG) bytes which should correspond to the ELF magic number
	 * and the next byte which indicates whether the file is 32-bit or 64-bit.
	 */
	if (p->stat.st_size < SELFMAG + 1)
		return 0;

	fd = open_proc(PROC_SELF, "fd/%d", lfd);
	if (fd < 0) {
		pr_err("Build-ID (For validation) could not be obtained for file %s because can't open the file\n",
		       rfe->name);
		return -1;
	}

	build_id_size = get_build_id(fd, &(p->stat), &build_id);
	close(fd);
	if (!build_id || build_id_size == -1)
		return 0;

	allocated_size = round_up(build_id_size, sizeof(uint32_t));
	rfe->build_id = xzalloc(allocated_size);
	if (!rfe->build_id) {
		pr_warn("Build-ID (For validation) could not be set for file %s\n", rfe->name);
		xfree(build_id);
		return -1;
	}

	rfe->n_build_id = allocated_size / sizeof(uint32_t);
	memcpy(rfe->build_id, (void *)build_id, build_id_size);

	xfree(build_id);
	return 1;
}

/*
 * This routine stores metadata about the open file (File size, build-id, CRC32C checksum)
 * so that validation can be done while restoring to make sure that the right file is
 * being restored.
 * Returns true if at least some metadata was stored, if there was an error it returns false.
 */
static bool store_validation_data(RegFileEntry *rfe, const struct fd_parms *p, int lfd)
{
	int result = 1;

	rfe->has_size = true;
	rfe->size = p->stat.st_size;

	if (opts.file_validation_method == FILE_VALIDATION_BUILD_ID)
		result = store_validation_data_build_id(rfe, lfd, p);

	if (result == -1)
		return false;

	if (!result)
		pr_info("Only file size could be stored for validation for file %s\n", rfe->name);
	return true;
}

int dump_one_reg_file(int lfd, u32 id, const struct fd_parms *p)
{
	struct fd_link _link, *link;
	struct mount_info *mi;
	struct cr_img *rimg;
	char ext_id[64];
	int ret;
	FileEntry fe = FILE_ENTRY__INIT;
	RegFileEntry rfe = REG_FILE_ENTRY__INIT;
	bool skip_for_shell_job = false;

	if (!p->link) {
		if (fill_fdlink(lfd, p, &_link))
			return -1;
		link = &_link;
	} else
		link = p->link;

	snprintf(ext_id, sizeof(ext_id), "file[%x:%" PRIx64 "]", p->mnt_id, p->stat.st_ino);
	if (external_lookup_id(ext_id)) {
		/* the first symbol will be cut on restore to get an relative path*/
		rfe.name = xstrdup(ext_id);
		rfe.ext = true;
		rfe.has_ext = true;
		goto ext;
	}

	mi = lookup_mnt_id(p->mnt_id);
	if (mi == NULL) {
		if (opts.shell_job && is_tty(p->stat.st_rdev, p->stat.st_dev)) {
			skip_for_shell_job = true;
		} else {
			pr_err("Can't lookup mount=%d for fd=%d path=%s\n", p->mnt_id, p->fd, link->name + 1);
			return -1;
		}
	}

	if (!skip_for_shell_job && mnt_is_overmounted(mi)) {
		pr_err("Open files on overmounted mounts are not supported yet\n");
		return -1;
	}

	if (p->mnt_id >= 0 && (root_ns_mask & CLONE_NEWNS)) {
		rfe.mnt_id = p->mnt_id;
		rfe.has_mnt_id = true;
	}

	pr_info("Dumping path for %d fd via self %d [%s]\n", p->fd, lfd, &link->name[1]);

	/*
	 * The regular path we can handle should start with slash.
	 */
	if (link->name[1] != '/') {
		pr_err("The path [%s] is not supported\n", &link->name[1]);
		return -1;
	}

	if (!skip_for_shell_job && check_path_remap(link, p, lfd, id, mi->nsid))
		return -1;
	rfe.name = &link->name[1];
ext:
	rfe.id = id;
	rfe.flags = p->flags;
	rfe.pos = p->pos;
	rfe.fown = (FownEntry *)&p->fown;
	rfe.has_mode = true;
	rfe.mode = p->stat.st_mode;

	if (S_ISREG(p->stat.st_mode) && should_check_size(rfe.flags) && !store_validation_data(&rfe, p, lfd))
		return -1;

	fe.type = FD_TYPES__REG;
	fe.id = rfe.id;
	fe.reg = &rfe;

	rimg = img_from_set(glob_imgset, CR_FD_FILES);
	ret = pb_write_one(rimg, &fe, PB_FILE);

	if (rfe.build_id)
		xfree(rfe.build_id);

	return ret;
}

const struct fdtype_ops regfile_dump_ops = {
	.type = FD_TYPES__REG,
	.dump = dump_one_reg_file,
};

static void convert_path_from_another_mp(char *src, char *dst, int dlen, struct mount_info *smi, struct mount_info *dmi)
{
	int off;

	/*
	 * mi->mountpoint	./foo/bar
	 * mi->ns_mountpoint	/foo/bar
	 * rfi->path		foo/bar/baz
	 */
	off = strlen(smi->ns_mountpoint + 1);
	BUG_ON(strlen(smi->root) < strlen(dmi->root));

	/*
	 * Create paths relative to this mount.
	 * Absolute path to the mount point + difference between source
	 * and destination roots + path relative to the mountpoint.
	 */
	snprintf(dst, dlen, "./%s/%s/%s", dmi->ns_mountpoint + 1, smi->root + strlen(dmi->root), src + off);
}

static int linkat_hard(int odir, char *opath, int ndir, char *npath, uid_t uid, gid_t gid, int flags)
{
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
	struct __user_cap_header_struct hdr;
	int ret, old_fsuid = -1, old_fsgid = -1;
	int errno_save;

	ret = linkat(odir, opath, ndir, npath, flags);
	if (ret == 0)
		return 0;

	if (!((errno == EPERM || errno == EOVERFLOW) && (root_ns_mask & CLONE_NEWUSER))) {
		errno_save = errno;
		pr_warn("Can't link %s -> %s\n", opath, npath);
		errno = errno_save;
		return ret;
	}

	/*
	 * Kernel before 4.3 has strange security restrictions about
	 * linkat. If the fsuid of the caller doesn't equals
	 * the uid of the file and the file is not "safe"
	 * one, then only global CAP_CHOWN will be allowed
	 * to link().
	 *
	 * Next, when we're in user namespace we're ns root,
	 * but not global CAP_CHOWN. Thus, even though we
	 * ARE ns root, we will not be allowed to link() at
	 * files that belong to regular users %)
	 *
	 * Fortunately, the setfsuid() requires ns-level
	 * CAP_SETUID which we have.
	 *
	 * Starting with 4.8 the kernel doesn't allow to create inodes
	 * with a uid or gid unknown to an user namespace.
	 * 036d523641c66 ("vfs: Don't create inodes with a uid or gid unknown to the vfs")
	 */

	old_fsuid = setfsuid(uid);
	old_fsgid = setfsgid(gid);

	/* AT_EMPTY_PATH requires CAP_DAC_READ_SEARCH */
	if (flags & AT_EMPTY_PATH) {
		hdr.version = _LINUX_CAPABILITY_VERSION_3;
		hdr.pid = 0;

		if (capget(&hdr, data) < 0) {
			errno_save = errno;
			pr_perror("capget");
			goto out;
		}
		data[0].effective = data[0].permitted;
		data[1].effective = data[1].permitted;
		if (capset(&hdr, data) < 0) {
			errno_save = errno;
			pr_perror("capset");
			goto out;
		}
	}

	ret = linkat(odir, opath, ndir, npath, flags);
	errno_save = errno;
	if (ret < 0)
		pr_perror("Can't link %s -> %s", opath, npath);

out:
	setfsuid(old_fsuid);
	setfsgid(old_fsgid);
	if (setfsuid(-1) != old_fsuid) {
		pr_warn("Failed to restore old fsuid!\n");
		/*
		 * Don't fail here. We still have chances to run till
		 * the pie/restorer, and if _this_ guy fails to set
		 * the proper fsuid, then we'll abort the restore.
		 */
	}

	/*
	 * Restoring PR_SET_DUMPABLE flag is required after setfsuid,
	 * as if it not set, proc inode will be created with root cred
	 * (see proc_pid_make_inode), which will result in permission
	 * check fail when trying to access files in /proc/self/
	 */
	prctl(PR_SET_DUMPABLE, 1, 0);

	errno = errno_save;

	return ret;
}

int rm_parent_dirs(int mntns_root, char *path, int count)
{
	char *p, *prev = NULL;
	int ret = -1;

	while (count-- > 0) {
		p = strrchr(path, '/');
		if (p) {
			/* We don't handle "//" in path */
			BUG_ON(prev && (prev - p == 1));
			*p = '\0';
		} else {
			/* Inconsistent path and count */
			pr_perror("Can't strrchr \"/\" in \"%s\"/\"%s\"]"
				  " left count=%d\n",
				  path, prev ? prev + 1 : "", count + 1);
			goto err;
		}

		if (prev)
			*prev = '/';
		prev = p;

		if (unlinkat(mntns_root, path, AT_REMOVEDIR)) {
			pr_perror("Can't remove %s AT %d", path, mntns_root);
			goto err;
		}
		pr_debug("Unlinked parent dir: %s AT %d\n", path, mntns_root);
	}

	ret = 0;
err:
	if (prev)
		*prev = '/';

	return ret;
}

/* Construct parent dir name and mkdir parent/grandparents if they're not exist */
int make_parent_dirs_if_need(int mntns_root, char *path)
{
	char *p, *last_delim;
	int err, count = 0;
	struct stat st;

	p = last_delim = strrchr(path, '/');
	if (!p)
		return 0;
	*p = '\0';

	if (fstatat(mntns_root, path, &st, AT_EMPTY_PATH) == 0)
		goto out;
	if (errno != ENOENT) {
		pr_perror("Can't stat %s", path);
		count = -1;
		goto out;
	}

	p = path;
	do {
		p = strchr(p, '/');
		if (p)
			*p = '\0';

		err = mkdirat(mntns_root, path, 0777);
		if (err && errno != EEXIST) {
			pr_perror("Can't create dir: %s AT %d", path, mntns_root);
			/* Failing anyway -> no retcode check */
			rm_parent_dirs(mntns_root, path, count);
			count = -1;
			goto out;
		} else if (!err) {
			pr_debug("Created parent dir: %s AT %d\n", path, mntns_root);
			count++;
		}

		if (p)
			*p++ = '/';
	} while (p);
out:
	*last_delim = '/';
	return count;
}

/*
 * This routine properly resolves d's path handling ghost/link-remaps.
 * The open_cb is a routine that does actual open, it differs for
 * files, directories, fifos, etc.
 *
 * Return 0 on success, -1 on error and 1 to indicate soft error, which can be
 * retried.
 */

static int rfi_remap(struct reg_file_info *rfi, int *level)
{
	struct mount_info *mi, *rmi, *tmi;
	char _path[PATH_MAX], *path = _path;
	char _rpath[PATH_MAX], *rpath = _rpath;
	int mntns_root;

	if (rfi->rfe->mnt_id == -1) {
		/* Know nothing about mountpoints */
		mntns_root = mntns_get_root_by_mnt_id(-1);
		path = rfi->path;
		rpath = rfi->remap->rpath;
		goto out_root;
	}

	mi = lookup_mnt_id(rfi->rfe->mnt_id);
	if (mi == NULL)
		return -1;

	if (rfi->rfe->mnt_id == rfi->remap->rmnt_id) {
		/* Both links on the same mount point */
		tmi = mi;
		path = rfi->path;
		rpath = rfi->remap->rpath;
		goto out;
	}

	rmi = lookup_mnt_id(rfi->remap->rmnt_id);
	if (rmi == NULL)
		return -1;

	/*
	 * Find the common bind-mount. We know that one mount point was
	 * really mounted and all other were bind-mounted from it, so the
	 * lowest mount must contains all bind-mounts.
	 */
	for (tmi = mi; tmi->bind; tmi = tmi->bind)
		;

	BUG_ON(tmi->s_dev != rmi->s_dev);
	BUG_ON(tmi->s_dev != mi->s_dev);

	/* Calculate paths on the device (root mount) */
	convert_path_from_another_mp(rfi->path, path, sizeof(_path), mi, tmi);
	convert_path_from_another_mp(rfi->remap->rpath, rpath, sizeof(_rpath), rmi, tmi);

out:
	mntns_root = mntns_get_root_fd(tmi->nsid);

	/* We get here while in task's mntns */
	if (try_remount_writable(tmi, true))
		return -1;

	pr_debug("%d: Link %s -> %s\n", tmi->mnt_id, rpath, path);
out_root:
	*level = make_parent_dirs_if_need(mntns_root, path);
	if (*level < 0)
		return -1;

	if (linkat_hard(mntns_root, rpath, mntns_root, path, rfi->remap->uid, rfi->remap->gid, 0) < 0) {
		int errno_saved = errno;

		if (!rm_parent_dirs(mntns_root, path, *level) && errno_saved == EEXIST) {
			errno = errno_saved;
			return 1;
		}
		return -1;
	}

	return 0;
}

/*
 * Compares the file's build-id with the stored value.
 * Returns 1 if the build-id of the file matches the build-id that was stored
 * while dumping, -1 if there is a mismatch or 0 if the build-id has not been
 * stored or could not be obtained.
 */
static int validate_with_build_id(const int fd, const struct stat *fd_status, const struct reg_file_info *rfi)
{
	unsigned char *build_id;
	int build_id_size;

	if (!rfi->rfe->has_size)
		return 1;

	if (!rfi->rfe->n_build_id)
		return 0;

	build_id = NULL;
	build_id_size = get_build_id(fd, fd_status, &build_id);
	if (!build_id || build_id_size == -1)
		return 0;

	if (round_up(build_id_size, sizeof(uint32_t)) != rfi->rfe->n_build_id * sizeof(uint32_t)) {
		pr_err("File %s has bad build-ID length %d (expect %d)\n", rfi->path,
		       round_up(build_id_size, sizeof(uint32_t)), (int)(rfi->rfe->n_build_id * sizeof(uint32_t)));
		xfree(build_id);
		return -1;
	}

	if (memcmp(build_id, rfi->rfe->build_id, build_id_size)) {
		pr_err("File %s has bad build-ID\n", rfi->path);
		xfree(build_id);
		return -1;
	}

	xfree(build_id);
	return 1;
}

/*
 * This function determines whether it was the same file that was open during dump
 * by checking the file's size, build-id and/or checksum with the same metadata
 * that was stored before dumping.
 * Checksum is calculated with CRC32C.
 * Returns true if the metadata of the file matches the metadata stored while
 * dumping else returns false.
 */
static bool validate_file(const int fd, const struct stat *fd_status, const struct reg_file_info *rfi)
{
	int result = 1;

	if (rfi->rfe->has_size && (fd_status->st_size != rfi->rfe->size)) {
		pr_err("File %s has bad size %" PRIu64 " (expect %" PRIu64 ")\n", rfi->path, fd_status->st_size,
		       rfi->rfe->size);
		return false;
	}

	if (opts.file_validation_method == FILE_VALIDATION_BUILD_ID)
		result = validate_with_build_id(fd, fd_status, rfi);

	if (result == -1)
		return false;

	if (!result)
		pr_info("File %s could only be validated with file size\n", rfi->path);
	return true;
}

int open_path(struct file_desc *d, int (*open_cb)(int mntns_root, struct reg_file_info *, void *), void *arg)
{
	int tmp = -1, mntns_root, level = 0;
	struct reg_file_info *rfi;
	char *orig_path = NULL;
	char path[PATH_MAX];
	int inh_fd = -1;
	int ret;

	if (inherited_fd(d, &tmp))
		return tmp;

	rfi = container_of(d, struct reg_file_info, d);

	if (rfi->rfe->ext) {
		tmp = inherit_fd_lookup_id(rfi->rfe->name);
		if (tmp >= 0) {
			inh_fd = tmp;
			/*
			 * PROC_SELF isn't used, because only service
			 * descriptors can be used here.
			 */
			mntns_root = open_pid_proc(getpid());
			snprintf(path, sizeof(path), "fd/%d", tmp);
			orig_path = rfi->path;
			rfi->path = path;
			goto ext;
		}
	}

	if (rfi->remap) {
		if (fault_injected(FI_RESTORE_OPEN_LINK_REMAP)) {
			pr_info("fault: Open link-remap failure!\n");
			kill(getpid(), SIGKILL);
		}

		mutex_lock(remap_open_lock);
		if (rfi->remap->is_dir) {
			/*
			 * FIXME Can't make directory under new name.
			 * Will have to open it under the ghost one :(
			 */
			orig_path = rfi->path;
			rfi->path = rfi->remap->rpath;
		} else if ((ret = rfi_remap(rfi, &level)) == 1) {
			static char tmp_path[PATH_MAX];

			/*
			 * The file whose name we're trying to create
			 * exists. Need to pick some other one, we're
			 * going to remove it anyway.
			 *
			 * Strictly speaking, this is cheating, file
			 * name shouldn't change. But since NFS with
			 * its silly-rename doesn't care, why should we?
			 */

			orig_path = rfi->path;
			rfi->path = tmp_path;
			snprintf(tmp_path, sizeof(tmp_path), "%s.cr_link", orig_path);
			pr_debug("Fake %s -> %s link\n", rfi->remap->rpath, rfi->path);

			if (rfi_remap(rfi, &level)) {
				pr_perror("Can't create even fake link!");
				goto err;
			}
		} else if (ret < 0) {
			pr_perror("Can't link %s -> %s", rfi->remap->rpath, rfi->path);
			goto err;
		}
	}

	mntns_root = mntns_get_root_by_mnt_id(rfi->rfe->mnt_id);
ext:
	tmp = open_cb(mntns_root, rfi, arg);
	if (tmp < 0) {
		pr_perror("Can't open file %s", rfi->path);
		close_safe(&inh_fd);
		goto err;
	}
	close_safe(&inh_fd);

	if ((rfi->rfe->has_size || rfi->rfe->has_mode) && !rfi->size_mode_checked) {
		struct stat st;

		if (fstat(tmp, &st) < 0) {
			pr_perror("Can't fstat opened file");
			goto err;
		}

		if (!validate_file(tmp, &st, rfi))
			goto err;

		if (rfi->rfe->has_mode) {
			mode_t curr_mode = st.st_mode;
			mode_t saved_mode = rfi->rfe->mode;

			if (opts.skip_file_rwx_check) {
				curr_mode &= ~(S_IRWXU | S_IRWXG | S_IRWXO);
				saved_mode &= ~(S_IRWXU | S_IRWXG | S_IRWXO);
			}

			if (curr_mode != saved_mode) {
				pr_err("File %s has bad mode 0%o (expect 0%o)\n"
				       "File r/w/x checks can be skipped with the --skip-file-rwx-check option\n",
				       rfi->path, (int)curr_mode, saved_mode);
				goto err;
			}
		}

		/*
		 * This is only visible in the current process, so
		 * change w/o locks. Other tasks sharing the same
		 * file will get one via unix sockets.
		 */
		rfi->size_mode_checked = true;
	}

	if (rfi->remap) {
		if (!rfi->remap->is_dir) {
			struct mount_info *mi = lookup_mnt_id(rfi->rfe->mnt_id);

			if (mi && try_remount_writable(mi, true))
				goto err;

			pr_debug("Unlink: %d:%s\n", rfi->rfe->mnt_id, rfi->path);
			if (unlinkat(mntns_root, rfi->path, 0)) {
				pr_perror("Failed to unlink the remap file");
				goto err;
			}
			if (rm_parent_dirs(mntns_root, rfi->path, level))
				goto err;
		}

		mutex_unlock(remap_open_lock);
	}
	if (orig_path)
		rfi->path = orig_path;

	if (restore_fown(tmp, rfi->rfe->fown)) {
		close(tmp);
		return -1;
	}

	return tmp;
err:
	if (rfi->remap)
		mutex_unlock(remap_open_lock);
	close_safe(&tmp);
	return -1;
}

int do_open_reg_noseek_flags(int ns_root_fd, struct reg_file_info *rfi, void *arg)
{
	u32 flags = *(u32 *)arg;
	int fd;

	/* unnamed temporary files are restored as ghost files */
	flags &= ~O_TMPFILE;

	fd = openat(ns_root_fd, rfi->path, flags);
	if (fd < 0) {
		pr_perror("Can't open file %s on restore", rfi->path);
		return fd;
	}

	return fd;
}

static int do_open_reg_noseek(int ns_root_fd, struct reg_file_info *rfi, void *arg)
{
	return do_open_reg_noseek_flags(ns_root_fd, rfi, &rfi->rfe->flags);
}

static int do_open_reg(int ns_root_fd, struct reg_file_info *rfi, void *arg)
{
	int fd;

	fd = do_open_reg_noseek(ns_root_fd, rfi, arg);
	if (fd < 0)
		return fd;

	/*
	 * O_PATH opened files carry empty fops in kernel,
	 * just ignore positioning at all.
	 */
	if (!(rfi->rfe->flags & O_PATH)) {
		if (rfi->rfe->pos != -1ULL && lseek(fd, rfi->rfe->pos, SEEK_SET) < 0) {
			pr_perror("Can't restore file pos");
			close(fd);
			return -1;
		}
	}

	return fd;
}

int open_reg_fd(struct file_desc *fd)
{
	return open_path(fd, do_open_reg_noseek, NULL);
}

int open_reg_by_id(u32 id)
{
	struct file_desc *fd;

	/*
	 * This one gets called by exe link, chroot and cwd
	 * restoring code. No need in calling lseek on either
	 * of them.
	 */

	fd = find_file_desc_raw(FD_TYPES__REG, id);
	if (fd == NULL) {
		pr_err("Can't find regfile for %#x\n", id);
		return -1;
	}

	return open_reg_fd(fd);
}

struct filemap_ctx {
	u32 flags;
	struct file_desc *desc;
	int fd;
	/*
	 * Whether or not to close the fd when we're about to
	 * put a new one into ctx.
	 *
	 * True is used by premap, so that it just calls vm_open
	 * in sequence, immediately mmap()s the file, then it
	 * can be closed.
	 *
	 * False is used by open_vmas() which pre-opens the files
	 * for restorer, and the latter mmap()s them and closes.
	 *
	 * ...
	 */
	bool close;
	/* ...
	 *
	 * but closing all vmas won't work, as some of them share
	 * the descriptor, so only the ones that terminate the
	 * fd-sharing chain are marked with VMA_CLOSE flag, saying
	 * restorer to close the vma's fd.
	 *
	 * Said that, this vma pointer references the previously
	 * seen vma, so that once fd changes, this one gets the
	 * closing flag.
	 */
	struct vma_area *vma;
};

static struct filemap_ctx ctx;

void filemap_ctx_init(bool auto_close)
{
	ctx.desc = NULL; /* to fail the first comparison in open_ */
	ctx.fd = -1;	 /* not to close random fd in _fini */
	ctx.vma = NULL;	 /* not to put spurious VMA_CLOSE in _fini */
	/* flags may remain any */
	ctx.close = auto_close;
}

void filemap_ctx_fini(void)
{
	if (ctx.close) {
		if (ctx.fd >= 0)
			close(ctx.fd);
	} else {
		if (ctx.vma)
			ctx.vma->e->status |= VMA_CLOSE;
	}
}

static int open_filemap(int pid, struct vma_area *vma)
{
	u32 flags;
	int ret;
	int plugin_fd = -1;

	/*
	 * The vma->fd should have been assigned in collect_filemap
	 *
	 * We open file w/o lseek, as mappings don't care about it
	 */

	BUG_ON((vma->vmfd == NULL) || !vma->e->has_fdflags);
	flags = vma->e->fdflags;

	/* update the new device file page offsets and file paths set during restore */
	if (vma->e->status & VMA_EXT_PLUGIN) {
		uint64_t new_pgoff;
		int ret;

		struct reg_file_info *rfi = container_of(vma->vmfd, struct reg_file_info, d);
		ret = run_plugins(UPDATE_VMA_MAP, rfi->rfe->name, vma->e->start, vma->e->pgoff, &new_pgoff, &plugin_fd);
		if (ret == 1) {
			pr_info("New mmap %#016" PRIx64 ":%#016" PRIx64 "->%#016" PRIx64 " fd %d\n", vma->e->start,
				vma->e->pgoff, new_pgoff, plugin_fd);
			vma->e->pgoff = new_pgoff;
		}
		/* Device plugin will restore vma contents, so no need for write permission */
		vma->e->status |= VMA_NO_PROT_WRITE;
	}

	if (ctx.flags != flags || ctx.desc != vma->vmfd) {
		if (plugin_fd >= 0) {
			/*
			 * Vma handled by device plugin.
			 * Some device drivers (e.g DRM) only allow the file descriptor that was used to create vma to
			 * be used when calling mmap. In this case, use the FD returned by plugin. FD can be copied
			 * using dup because dup returns a reference to the same struct file inside kernel, but we
			 * cannot open a new FD.
			 */
			ret = dup(plugin_fd);
		} else if (vma->e->status & VMA_AREA_MEMFD) {
			ret = memfd_open(vma->vmfd, &flags);
		} else {
			ret = open_path(vma->vmfd, do_open_reg_noseek_flags, &flags);
		}
		if (ret < 0)
			return ret;

		filemap_ctx_fini();

		ctx.flags = flags;
		ctx.desc = vma->vmfd;
		ctx.fd = ret;
	}

	ctx.vma = vma;
	vma->e->fd = ctx.fd;
	return 0;
}

int collect_filemap(struct vma_area *vma)
{
	struct file_desc *fd;

	if (!vma->e->has_fdflags) {
		/* Make a wild guess for the fdflags */
		vma->e->has_fdflags = true;
		if ((vma->e->prot & PROT_WRITE) && vma_area_is(vma, VMA_FILE_SHARED))
			vma->e->fdflags = O_RDWR;
		else
			vma->e->fdflags = O_RDONLY;
	}

	if (vma->e->status & VMA_AREA_MEMFD)
		fd = collect_memfd(vma->e->shmid);
	else
		fd = collect_special_file(vma->e->shmid);
	if (!fd)
		return -1;

	vma->vmfd = fd;
	vma->vm_open = open_filemap;
	return 0;
}

static int open_fe_fd(struct file_desc *fd, int *new_fd)
{
	int tmp;

	tmp = open_path(fd, do_open_reg, NULL);
	if (tmp < 0)
		return -1;
	*new_fd = tmp;
	return 0;
}

static char *reg_file_path(struct file_desc *d, char *buf, size_t s)
{
	struct reg_file_info *rfi;

	rfi = container_of(d, struct reg_file_info, d);
	return rfi->path;
}

static struct file_desc_ops reg_desc_ops = {
	.type = FD_TYPES__REG,
	.open = open_fe_fd,
	.name = reg_file_path,
};

struct file_desc *try_collect_special_file(u32 id, int optional)
{
	struct file_desc *fdesc;

	/*
	 * Files dumped for vmas/exe links can have remaps
	 * configured. Need to bump-up users for them, otherwise
	 * the open_path() would unlink the remap file after
	 * the very first open.
	 */

	fdesc = find_file_desc_raw(FD_TYPES__REG, id);
	if (fdesc == NULL) {
		if (!optional)
			pr_err("No entry for reg-file-ID %#x\n", id);
		return NULL;
	}

	return fdesc;
}

static int collect_one_regfile(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct reg_file_info *rfi = o;
	static char dot[] = ".";

	rfi->rfe = pb_msg(base, RegFileEntry);
	/* change "/foo" into "foo" and "/" into "." */
	if (rfi->rfe->name[1] == '\0')
		rfi->path = dot;
	else
		rfi->path = rfi->rfe->name + 1;
	rfi->remap = NULL;
	rfi->size_mode_checked = false;

	pr_info("Collected [%s] ID %#x\n", rfi->path, rfi->rfe->id);
	return file_desc_add(&rfi->d, rfi->rfe->id, &reg_desc_ops);
}

struct collect_image_info reg_file_cinfo = {
	.fd_type = CR_FD_REG_FILES,
	.pb_type = PB_REG_FILE,
	.priv_size = sizeof(struct reg_file_info),
	.collect = collect_one_regfile,
	.flags = COLLECT_SHARED,
};

int collect_remaps_and_regfiles(void)
{
	if (!files_collected() && collect_image(&reg_file_cinfo))
		return -1;

	if (collect_image(&remap_cinfo))
		return -1;

	return 0;
}
