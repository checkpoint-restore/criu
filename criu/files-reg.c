#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/prctl.h>
#include <ctype.h>
#include <sched.h>

/* Stolen from kernel/fs/nfs/unlink.c */
#define SILLYNAME_PREF ".nfs"
#define SILLYNAME_SUFF_LEN (((unsigned)sizeof(u64) << 1) + ((unsigned)sizeof(unsigned int) << 1))

#include "cr_options.h"
#include "imgset.h"
#include "file-ids.h"
#include "mount.h"
#include "files.h"
#include "image.h"
#include "list.h"
#include "util.h"
#include "fs-magic.h"
#include "asm/atomic.h"
#include "namespaces.h"
#include "proc_parse.h"
#include "pstree.h"

#include "protobuf.h"
#include "images/regfile.pb-c.h"
#include "images/remap-file-path.pb-c.h"

#include "files-reg.h"
#include "plugin.h"

int setfsuid(uid_t fsuid);

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

static LIST_HEAD(remaps);

/*
 * Remember the name to delete it if needed on error or
 * rollback action. Note we don't expect that there will
 * be a HUGE number of link remaps, so in a sake of speed
 * we keep all data in memory.
 */
struct link_remap_rlb {
	struct list_head	list;
	struct ns_id		*mnt_ns;
	char			*path;
};

static int note_link_remap(char *path, struct ns_id *nsid)
{
	struct link_remap_rlb *rlb;

	rlb = xmalloc(sizeof(*rlb));
	if (!rlb)
		goto err;

	rlb->path = strdup(path);
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

static int mkreg_ghost(char *path, u32 mode, struct ghost_file *gf, struct cr_img *img)
{
	int gfd, ret;

	gfd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
	if (gfd < 0)
		return -1;

	ret = copy_file(img_raw_fd(img), gfd, 0);
	if (ret < 0)
		unlink(path);
	close(gfd);

	return ret;
}

static int ghost_apply_metadata(const char *path, GhostFileEntry *gfe)
{
	struct timeval tv[2];
	int ret = -1;

	if (chown(path, gfe->uid, gfe->gid) < 0) {
		pr_perror("Can't reset user/group on ghost %s", path);
		goto err;
	}

	if (chmod(path, gfe->mode)) {
		pr_perror("Can't set perms %o on ghost %s", gfe->mode, path);
		goto err;
	}

	if (gfe->atim) {
		tv[0].tv_sec = gfe->atim->tv_sec;
		tv[0].tv_usec = gfe->atim->tv_usec;
		tv[1].tv_sec = gfe->mtim->tv_sec;
		tv[1].tv_usec = gfe->mtim->tv_usec;
		if (lutimes(path, tv)) {
			pr_perror("Can't set access and modufication times on ghost %s", path);
			goto err;
		}
	}

	ret = 0;
err:
	return ret;
}

static int create_ghost(struct ghost_file *gf, GhostFileEntry *gfe, struct cr_img *img)
{
	char path[PATH_MAX];
	int ret, root_len;
	char *msg;

	root_len = ret = rst_get_mnt_root(gf->remap.rmnt_id, path, sizeof(path));
	if (ret < 0) {
		pr_err("The %d mount is not found for ghost\n", gf->remap.rmnt_id);
		goto err;
	}

	snprintf(path + ret, sizeof(path) - ret, "/%s", gf->remap.rpath);
	ret = -1;
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
		if ((ret = mkdir(path, gfe->mode)) < 0) {
			pr_perror("Can't make ghost dir");
			goto err;
		}
	} else {
		if ((ret = mkreg_ghost(path, gfe->mode, gf, img)) < 0)
			msg = "Can't create ghost regfile\n";
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

	strcpy(gf->remap.rpath, path + root_len + 1);
	pr_debug("Remap rpath is %s\n", gf->remap.rpath);

	ret = -1;
	if (ghost_apply_metadata(path, gfe))
		goto err;

	ret = 0;
err:
	return ret;
}

static inline void ghost_path(char *path, int plen,
		struct reg_file_info *rfi, RemapFilePathEntry *rfe)
{
	snprintf(path, plen, "%s.cr.%x.ghost", rfi->path, rfe->remap_id);
}

static int open_remap_ghost(struct reg_file_info *rfi,
		RemapFilePathEntry *rfe)
{
	struct ghost_file *gf;
	GhostFileEntry *gfe = NULL;
	struct cr_img *img;

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

	gf->remap.rpath = xmalloc(PATH_MAX);
	if (!gf->remap.rpath)
		goto err;

	img = open_image(CR_FD_GHOST_FILE, O_RSTR, rfe->remap_id);
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
		strncpy(gf->remap.rpath, rfi->path, PATH_MAX);
	else
		ghost_path(gf->remap.rpath, PATH_MAX, rfi, rfe);

	if (create_ghost(gf, gfe, img))
		goto close_ifd;

	ghost_file_entry__free_unpacked(gfe, NULL);
	close_image(img);

	gf->id = rfe->remap_id;
	gf->remap.users = 0;
	gf->remap.is_dir = S_ISDIR(gfe->mode);
	gf->remap.owner = gfe->uid;
	list_add_tail(&gf->list, &ghost_files);
gf_found:
	rfi->is_dir = gf->remap.is_dir;
	rfi->remap = &gf->remap;
	return 0;

close_ifd:
	close_image(img);
err:
	if (gfe)
		ghost_file_entry__free_unpacked(gfe, NULL);
	xfree(gf->remap.rpath);
	shfree_last(gf);
	return -1;
}

static int open_remap_linked(struct reg_file_info *rfi,
		RemapFilePathEntry *rfe)
{
	struct file_remap *rm;
	struct file_desc *rdesc;
	struct reg_file_info *rrfi;
	uid_t owner = -1;

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

	if (root_ns_mask & CLONE_NEWUSER) {
		int rfd;
		struct stat st;

		rfd = mntns_get_root_by_mnt_id(rfi->rfe->mnt_id);
		if (fstatat(rfd, rrfi->path, &st, AT_SYMLINK_NOFOLLOW)) {
			pr_perror("Can't get owner of link remap %s", rrfi->path);
			xfree(rm);
			return -1;
		}

		owner = st.st_uid;
	}

	rm->rpath = rrfi->path;
	rm->users = 0;
	rm->is_dir = false;
	rm->owner = owner;
	rm->rmnt_id = rfi->rfe->mnt_id;
	rfi->remap = rm;
	return 0;
}

static int open_remap_dead_process(struct reg_file_info *rfi,
		RemapFilePathEntry *rfe)
{
	struct pstree_item *helper;

	for_each_pstree_item(helper) {
		/* don't need to add multiple tasks */
		if (helper->pid.virt == rfe->remap_id) {
			pr_info("Skipping helper for restoring /proc/%d; pid exists\n", rfe->remap_id);
			return 0;
		}
	}

	helper = alloc_pstree_helper();
	if (!helper)
		return -1;

	helper->sid = root_item->sid;
	helper->pgid = root_item->pgid;
	helper->pid.virt = rfe->remap_id;
	helper->parent = root_item;
	list_add_tail(&helper->sibling, &root_item->children);

	pr_info("Added a helper for restoring /proc/%d\n", helper->pid.virt);

	return 0;
}

struct remap_info {
	struct list_head list;
	RemapFilePathEntry *rfe;
	struct reg_file_info *rfi;
};

static int collect_one_remap(void *obj, ProtobufCMessage *msg, struct cr_img *i)
{
	struct remap_info *ri = obj;
	RemapFilePathEntry *rfe;
	struct file_desc *fdesc;

	ri->rfe = rfe = pb_msg(msg, RemapFilePathEntry);

	if (!rfe->has_remap_type) {
		rfe->has_remap_type = true;
		/* backward compatibility with images */
		if (rfe->remap_id & REMAP_GHOST) {
			rfe->remap_id &= ~REMAP_GHOST;
			rfe->remap_type = REMAP_TYPE__GHOST;
		} else
			rfe->remap_type = REMAP_TYPE__LINKED;
	}

	fdesc = find_file_desc_raw(FD_TYPES__REG, rfe->orig_id);
	if (fdesc == NULL) {
		pr_err("Remap for non existing file %#x\n", rfe->orig_id);
		return -1;
	}

	ri->rfi = container_of(fdesc, struct reg_file_info, d);

	list_add_tail(&ri->list, &remaps);

	return 0;
}

static int prepare_one_remap(struct remap_info *ri)
{
	int ret = -1;
	RemapFilePathEntry *rfe = ri->rfe;
	struct reg_file_info *rfi = ri->rfi;

	pr_info("Configuring remap %#x -> %#x\n", rfi->rfe->id, rfe->remap_id);

	switch (rfe->remap_type) {
	case REMAP_TYPE__LINKED:
		ret = open_remap_linked(rfi, rfe);
		break;
	case REMAP_TYPE__GHOST:
		ret = open_remap_ghost(rfi, rfe);
		break;
	case REMAP_TYPE__PROCFS:
		/* handled earlier by prepare_procfs_remaps */
		ret = 0;
		break;
	default:
		pr_err("unknown remap type %u\n", rfe->remap_type);
		goto out;
	}

out:
	return ret;
}

/* We separate the prepartion of PROCFS remaps because they allocate pstree
 * items, which need to be seen by the root task. We can't do all remaps here,
 * because the files haven't been loaded yet.
 */
int prepare_procfs_remaps(void)
{
	struct remap_info *ri;

	list_for_each_entry(ri, &remaps, list) {
		RemapFilePathEntry *rfe = ri->rfe;
		struct reg_file_info *rfi = ri->rfi;

		switch (rfe->remap_type) {
		case REMAP_TYPE__PROCFS:
			if (open_remap_dead_process(rfi, rfe) < 0)
				return -1;
			break;
		default:
			continue;
		}
	}

	return 0;
}

int prepare_remaps(void)
{
	struct remap_info *ri;
	int ret = 0;

	list_for_each_entry(ri, &remaps, list) {
		ret = prepare_one_remap(ri);
		if (ret)
			break;
	}

	return ret;
}

static void try_clean_ghost(struct remap_info *ri)
{
	char path[PATH_MAX];
	int mnt_id, ret;

	mnt_id = ri->rfi->rfe->mnt_id; /* rirfirfe %) */
	ret = rst_get_mnt_root(mnt_id, path, sizeof(path));
	if (ret < 0)
		return;

	if (ri->rfi->remap == NULL)
		return;
	if (!ri->rfi->is_dir) {
		ghost_path(path + ret, sizeof(path) - 1, ri->rfi, ri->rfe);
		if (!unlink(path)) {
			pr_info(" `- X [%s] ghost\n", path);
			return;
		}
	} else {
		strncpy(path + ret, ri->rfi->path, sizeof(path) - 1);
		if (!rmdir(path)) {
			pr_info(" `- Xd [%s] ghost\n", path);
			return;
		}
	}

	pr_perror(" `- XFail [%s] ghost", path);
}

void try_clean_remaps(int ns_fd)
{
	struct remap_info *ri;
	int old_ns = -1;
	int cwd_fd = -1;

	if (list_empty(&remaps))
		goto out;

	if (ns_fd >= 0) {
		pr_info("Switching to new ns to clean ghosts\n");

		old_ns = open_proc(PROC_SELF, "ns/mnt");
		if (old_ns < 0) {
			pr_perror("`- Can't keep old ns");
			return;
		}

		cwd_fd = open(".", O_DIRECTORY);
		if (cwd_fd < 0) {
			pr_perror("Unable to open cwd");
			return;
		}

		if (setns(ns_fd, CLONE_NEWNS) < 0) {
			close(old_ns);
			close(cwd_fd);
			pr_perror("`- Can't switch");
			return;
		}
	}

	list_for_each_entry(ri, &remaps, list)
		if (ri->rfe->remap_type == REMAP_TYPE__GHOST)
			try_clean_ghost(ri);

	if (old_ns >= 0) {
		if (setns(old_ns, CLONE_NEWNS) < 0)
			pr_perror("Fail to switch back!");
		close(old_ns);
	}

	if (cwd_fd >= 0) {
		if (fchdir(cwd_fd)) {
			pr_perror("Unable to restore cwd");
			close(cwd_fd);
			return;
		}
		close(cwd_fd);
	}

out:
	if (ns_fd >= 0)
		close(ns_fd);
}

static struct collect_image_info remap_cinfo = {
	.fd_type = CR_FD_REMAP_FPATH,
	.pb_type = PB_REMAP_FPATH,
	.priv_size = sizeof(struct remap_info),
	.collect = collect_one_remap,
};

static int dump_ghost_file(int _fd, u32 id, const struct stat *st, dev_t phys_dev)
{
	struct cr_img *img;
	GhostFileEntry gfe = GHOST_FILE_ENTRY__INIT;
	Timeval atim = TIMEVAL__INIT, mtim = TIMEVAL__INIT;

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
		ret = copy_file(fd, img_raw_fd(img), st->st_size);
		close(fd);
		if (ret)
			return -1;
	}

	close_image(img);
	return 0;
}

void remap_put(struct file_remap *remap)
{
	mutex_lock(ghost_file_mutex);
	if (--remap->users == 0) {
		int mntns_root;

		pr_info("Unlink the ghost %s\n", remap->rpath);

		mntns_root = mntns_get_root_by_mnt_id(remap->rmnt_id);
		unlinkat(mntns_root, remap->rpath, 0);
	}
	mutex_unlock(ghost_file_mutex);
}

struct file_remap *lookup_ghost_remap(u32 dev, u32 ino)
{
	struct ghost_file *gf;

	mutex_lock(ghost_file_mutex);
	list_for_each_entry(gf, &ghost_files, list) {
		if (gf->ino == ino && (gf->dev == dev)) {
			gf->remap.users++;
			mutex_unlock(ghost_file_mutex);
			return &gf->remap;
		}
	}
	mutex_unlock(ghost_file_mutex);

	return NULL;
}

static int dump_ghost_remap(char *path, const struct stat *st,
				int lfd, u32 id, struct ns_id *nsid)
{
	struct ghost_file *gf;
	RemapFilePathEntry rpe = REMAP_FILE_PATH_ENTRY__INIT;
	dev_t phys_dev;

	pr_info("Dumping ghost file for fd %d id %#x\n", lfd, id);

	if (st->st_size > opts.ghost_limit) {
		pr_err("Can't dump ghost file %s of %"PRIu64" size, increase limit\n",
				path, st->st_size);
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
	list_add_tail(&gf->list, &ghost_files);

	if (dump_ghost_file(lfd, gf->id, st, phys_dev))
		return -1;

dump_entry:
	rpe.orig_id = id;
	rpe.remap_id = gf->id;
	rpe.has_remap_type = true;
	rpe.remap_type = REMAP_TYPE__GHOST;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_REMAP_FPATH),
			&rpe, PB_REMAP_FPATH);
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

void delete_link_remaps(void) { __rollback_link_remaps(true); }
void free_link_remaps(void) { __rollback_link_remaps(false); }

static int create_link_remap(char *path, int len, int lfd,
				u32 *idp, struct ns_id *nsid)
{
	char link_name[PATH_MAX], *tmp;
	RegFileEntry rfe = REG_FILE_ENTRY__INIT;
	FownEntry fwn = FOWN_ENTRY__INIT;
	int mntns_root;

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
	tmp = link_name + len;
	while (*tmp != '/') {
		BUG_ON(tmp == link_name);
		tmp--;
	}

	fd_id_generate_special(NULL, idp);
	rfe.id		= *idp;
	rfe.flags	= 0;
	rfe.pos		= 0;
	rfe.fown	= &fwn;
	rfe.name	= link_name + 1;

	/* Any 'unique' name works here actually. Remap works by reg-file ids. */
	snprintf(tmp + 1, sizeof(link_name) - (size_t)(tmp - link_name - 1), "link_remap.%d", rfe.id);

	mntns_root = mntns_get_root_fd(nsid);

	if (linkat(lfd, "", mntns_root, link_name, AT_EMPTY_PATH) < 0) {
		pr_perror("Can't link remap to %s", path);
		return -1;
	}

	if (note_link_remap(link_name, nsid))
		return -1;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_REG_FILES), &rfe, PB_REG_FILE);
}

static int dump_linked_remap(char *path, int len, const struct stat *ost,
				int lfd, u32 id, struct ns_id *nsid)
{
	u32 lid;
	RemapFilePathEntry rpe = REMAP_FILE_PATH_ENTRY__INIT;

	if (create_link_remap(path, len, lfd, &lid, nsid))
		return -1;

	rpe.orig_id = id;
	rpe.remap_id = lid;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_REMAP_FPATH),
			&rpe, PB_REMAP_FPATH);
}

static pid_t *dead_pids;
static int n_dead_pids;

static int dead_pid_check_threads(struct pstree_item *item, pid_t pid)
{
	int i;

	for (i = 0; i < item->nr_threads; i++) {
		/*
		 * If the dead PID was given to a main thread of another
		 * process, this is handled during restore.
		 */
		if (item->pid.real == item->threads[i].real ||
		    item->threads[i].virt != pid)
			continue;

		pr_err("Conflict with a dead task with the same PID as of this thread (virt %d, real %d).\n",
			item->threads[i].virt, item->threads[i].real);
		return 1;
	}

	return 0;
}

int dead_pid_conflict(void)
{
	struct pstree_item *item;
	int i;

	for (i = 0; i < n_dead_pids; i++) {
		for_each_pstree_item(item)
			if (dead_pid_check_threads(item, dead_pids[i]))
				return 1;
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

	return pb_write_one(img_from_set(glob_imgset, CR_FD_REMAP_FPATH),
			&rpe, PB_REMAP_FPATH);
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

int strip_deleted(struct fd_link *link)
{
	struct dcache_prepends {
		const char	*str;
		size_t		len;
	} static const prepends[] = {
		{
			.str	= " (deleted)",
			.len	= 10,
		}, {
			.str	= "//deleted",
			.len	= 9,
		}
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(prepends); i++) {
		size_t at;

		if (link->len <= prepends[i].len)
			continue;

		at = link->len - prepends[i].len;
		if (!strcmp(&link->name[at], prepends[i].str)) {
			pr_debug("Strip '%s' tag from '%s'\n",
				 prepends[i].str, link->name);
			link->name[at] = '\0';
			link->len -= prepends[i].len;
			return 1;
		}
	}
	return 0;
}

static int check_path_remap(struct fd_link *link, const struct fd_parms *parms,
				int lfd, u32 id, struct ns_id *nsid)
{
	char *rpath = link->name;
	int plen = link->len;
	int ret, mntns_root;
	struct stat pst;
	const struct stat *ost = &parms->stat;

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
		if (!start)
			return -1;
		pid = strtol(start + 1, &end, 10);

		/* If strtol didn't convert anything, then we are looking at
		 * something like /proc/kmsg, which we shouldn't mess with.
		 * Anything under /proc/<pid> (including that directory itself)
		 * can be c/r'd with a dead pid remap, so let's allow all such
		 * cases.
		 */
		if (pid != 0) {
			bool is_dead = strip_deleted(link);

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
				is_dead = access(rpath, F_OK);
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
		strip_deleted(link);
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
		strip_deleted(link);
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
		return dump_linked_remap(rpath + 1, plen - 1, ost, lfd, id, nsid);
	}

	mntns_root = mntns_get_root_fd(nsid);
	if (mntns_root < 0)
		return -1;

	ret = fstatat(mntns_root, rpath, &pst, 0);
	if (ret < 0) {
		/*
		 * Linked file, but path is not accessible (unless any
		 * other error occurred). We can create a temporary link to it
		 * uning linkat with AT_EMPTY_PATH flag and remap it to this
		 * name.
		 */

		if (errno == ENOENT)
			return dump_linked_remap(rpath + 1, plen - 1,
							ost, lfd, id, nsid);

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
		 * by somebody else. We can dump it with linked remaps, but
		 * we'll have difficulties on restore -- we will have to
		 * move the exisint file aside, then restore this one,
		 * unlink, then move the original file back. It's fairly
		 * easy to do, but we don't do it now, since unlinked files
		 * have the "(deleted)" suffix in proc and name conflict
		 * is unlikely :)
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

static bool should_check_size(int flags)
{
	/* Skip size if file has O_APPEND and O_WRONLY flags (e.g. log file). */
	if (((flags & O_ACCMODE) == O_WRONLY) &&
			(flags & O_APPEND))
		return false;

	return true;
}

int dump_one_reg_file(int lfd, u32 id, const struct fd_parms *p)
{
	struct fd_link _link, *link;
	struct ns_id *nsid;
	struct cr_img *rimg;
	char ext_id[64];

	RegFileEntry rfe = REG_FILE_ENTRY__INIT;

	if (!p->link) {
		if (fill_fdlink(lfd, p, &_link))
			return -1;
		link = &_link;
	} else
		link = p->link;



	snprintf(ext_id, sizeof(ext_id), "file[%x:%"PRIx64"]", p->mnt_id, p->stat.st_ino);
	if (external_lookup_id(ext_id)) {
		/* the first symbol will be cut on restore to get an relative path*/
		rfe.name = xstrdup(ext_id);
		rfe.ext = true;
		rfe.has_ext = true;
		goto ext;
	}

	nsid = lookup_nsid_by_mnt_id(p->mnt_id);
	if (nsid == NULL) {
		pr_err("Can't lookup mount=%d for fd=%d path=%s\n",
			p->mnt_id, p->fd, link->name + 1);
		return -1;
	}

	if (p->mnt_id >= 0 && (root_ns_mask & CLONE_NEWNS)) {
		rfe.mnt_id = p->mnt_id;
		rfe.has_mnt_id = true;
	}

	pr_info("Dumping path for %d fd via self %d [%s]\n",
			p->fd, lfd, &link->name[1]);

	/*
	 * The regular path we can handle should start with slash.
	 */
	if (link->name[1] != '/') {
		pr_err("The path [%s] is not supported\n", &link->name[1]);
		return -1;
	}

	if (check_path_remap(link, p, lfd, id, nsid))
		return -1;
	rfe.name	= &link->name[1];
ext:
	rfe.id		= id;
	rfe.flags	= p->flags;
	rfe.pos		= p->pos;
	rfe.fown	= (FownEntry *)&p->fown;

	if (S_ISREG(p->stat.st_mode) && should_check_size(rfe.flags)) {
		rfe.has_size = true;
		rfe.size = p->stat.st_size;
	}

	rimg = img_from_set(glob_imgset, CR_FD_REG_FILES);
	return pb_write_one(rimg, &rfe, PB_REG_FILE);
}

const struct fdtype_ops regfile_dump_ops = {
	.type		= FD_TYPES__REG,
	.dump		= dump_one_reg_file,
};

static void convert_path_from_another_mp(char *src, char *dst, int dlen,
					struct mount_info *smi,
					struct mount_info *dmi)
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
	snprintf(dst, dlen, "%s/%s/%s",
				dmi->ns_mountpoint + 1,
				smi->root + strlen(dmi->root),
				src + off);
}

static int linkat_hard(int odir, char *opath, int ndir, char *npath, uid_t owner)
{
	int ret, old_fsuid = -1;
	int errno_save;

	ret = linkat(odir, opath, ndir, npath, 0);
	if (ret < 0)
		pr_perror("Can't link %s -> %s", opath, npath);
	if (ret == 0 || errno != EPERM || !(root_ns_mask & CLONE_NEWUSER))
		return ret;

	/*
	 * Kernel before 4.3 has strange secutiry restrictions about
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
	 */

	old_fsuid = setfsuid(owner);

	ret = linkat(odir, opath, ndir, npath, 0);
	errno_save = errno;
	if (ret < 0)
		pr_perror("Can't link %s -> %s", opath, npath);

	setfsuid(old_fsuid);
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

static void rm_parent_dirs(int mntns_root, char *path, int count)
{
	char *p, *prev = NULL;

	if (!count)
		return;

	while (count--) {
		p = strrchr(path, '/');
		if (p)
			*p = '\0';
		if (prev)
			*prev = '/';

		if (unlinkat(mntns_root, path, AT_REMOVEDIR))
			pr_perror("Can't remove %s AT %d", path, mntns_root);
		else
			pr_debug("Unlinked parent dir: %s AT %d\n", path, mntns_root);
		prev = p;
	}

	if (prev)
		*prev = '/';
}

/* Construct parent dir name and mkdir parent/grandparents if they're not exist */
static int make_parent_dirs_if_need(int mntns_root, char *path)
{
	char *p, *last_delim;
	int err, count = 0;
	struct stat st;

	p = last_delim = strrchr(path, '/');
	if (!p) {
		pr_err("Path %s has no parent dir", path);
		return -1;
	}
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
	if (rfi->rfe->mnt_id == rfi->remap->rmnt_id) {
		/* Both links on the same mount point */
		tmi = mi;
		path = rfi->path;
		rpath = rfi->remap->rpath;
		goto out;
	}

	rmi = lookup_mnt_id(rfi->remap->rmnt_id);

	/*
	 * Find the common bind-mount. We know that one mount point was
	 * really mounted and all other were bind-mounted from it, so the
	 * lowest mount must contains all bind-mounts.
	 */
	for (tmi = mi; tmi->bind; tmi = tmi->bind)
		;

	BUG_ON(tmi->s_dev != rmi->s_dev);
	BUG_ON(tmi->s_dev != mi->s_dev);

	/* Calcalate paths on the device (root mount) */
	convert_path_from_another_mp(rfi->path, path, sizeof(_path), mi, tmi);
	convert_path_from_another_mp(rfi->remap->rpath, rpath, sizeof(_rpath), rmi, tmi);

out:
	pr_debug("%d: Link %s -> %s\n", tmi->mnt_id, rpath, path);
	mntns_root = mntns_get_root_fd(tmi->nsid);

out_root:
	*level = make_parent_dirs_if_need(mntns_root, path);
	if (*level < 0)
		return -1;

	if (linkat_hard(mntns_root, rpath, mntns_root, path, rfi->remap->owner) < 0) {
		rm_parent_dirs(mntns_root, path, *level);
		return -1;
	}

	return 0;
}

int open_path(struct file_desc *d,
		int(*open_cb)(int mntns_root, struct reg_file_info *, void *), void *arg)
{
	int tmp, mntns_root, level;
	struct reg_file_info *rfi;
	char *orig_path = NULL;
	char path[PATH_MAX];

	if (inherited_fd(d, &tmp))
		return tmp;

	rfi = container_of(d, struct reg_file_info, d);

	if (rfi->rfe->ext) {
		tmp = inherit_fd_lookup_id(rfi->rfe->name);
		if (tmp >= 0) {
			mntns_root = open_pid_proc(PROC_SELF);
			snprintf(path, sizeof(path), "fd/%d", tmp);
			orig_path = rfi->path;
			rfi->path = path;
			goto ext;
		}
	}

	if (rfi->remap) {
		mutex_lock(ghost_file_mutex);
		if (rfi->remap->is_dir) {
			/*
			 * FIXME Can't make directory under new name.
			 * Will have to open it under the ghost one :(
			 */
			orig_path = rfi->path;
			rfi->path = rfi->remap->rpath;
		} else if (rfi_remap(rfi, &level) < 0) {
			static char tmp_path[PATH_MAX];

			if (errno != EEXIST) {
				pr_perror("Can't link %s -> %s", rfi->path,
						rfi->remap->rpath);
				return -1;
			}

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
			pr_debug("Fake %s -> %s link\n", rfi->path, rfi->remap->rpath);

			if (rfi_remap(rfi, &level) < 0) {
				pr_perror("Can't create even fake link!");
				return -1;
			}
		}
	}

	mntns_root = mntns_get_root_by_mnt_id(rfi->rfe->mnt_id);
ext:
	tmp = open_cb(mntns_root, rfi, arg);
	if (tmp < 0) {
		pr_perror("Can't open file %s", rfi->path);
		return -1;
	}

	if (rfi->rfe->has_size && !rfi->size_checked) {
		struct stat st;

		if (fstat(tmp, &st) < 0) {
			pr_perror("Can't fstat opened file");
			return -1;
		}

		if (st.st_size != rfi->rfe->size) {
			pr_err("File %s has bad size %"PRIu64" (expect %"PRIu64")\n",
					rfi->path, st.st_size,
					rfi->rfe->size);
			return -1;
		}

		/*
		 * This is only visible in the current process, so
		 * change w/o locks. Other tasks sharing the same
		 * file will get one via unix sockets.
		 */
		rfi->size_checked = true;
	}

	if (rfi->remap) {
		if (!rfi->remap->is_dir) {
			unlinkat(mntns_root, rfi->path, 0);
			rm_parent_dirs(mntns_root, rfi->path, level);
		}

		BUG_ON(!rfi->remap->users);
		if (--rfi->remap->users == 0) {
			pr_info("Unlink the ghost %s\n", rfi->remap->rpath);
			mntns_root = mntns_get_root_by_mnt_id(rfi->remap->rmnt_id);
			unlinkat(mntns_root, rfi->remap->rpath, rfi->remap->is_dir ? AT_REMOVEDIR : 0);
		}

		mutex_unlock(ghost_file_mutex);
	}
	if (orig_path)
		rfi->path = orig_path;

	if (restore_fown(tmp, rfi->rfe->fown))
		return -1;

	return tmp;
}

int do_open_reg_noseek_flags(int ns_root_fd, struct reg_file_info *rfi, void *arg)
{
	u32 flags = *(u32 *)arg;
	int fd;

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

	if ((rfi->rfe->pos != -1ULL) &&
			lseek(fd, rfi->rfe->pos, SEEK_SET) < 0) {
		pr_perror("Can't restore file pos");
		close(fd);
		return -1;
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

int get_filemap_fd(struct vma_area *vma)
{
	u32 flags;

	/*
	 * Thevma->fd should have been assigned in collect_filemap
	 *
	 * We open file w/o lseek, as mappings don't care about it
	 */

	BUG_ON(vma->vmfd == NULL);
	if (vma->e->has_fdflags)
		flags = vma->e->fdflags;
	else if ((vma->e->prot & PROT_WRITE) &&
			vma_area_is(vma, VMA_FILE_SHARED))
		flags = O_RDWR;
	else
		flags = O_RDONLY;

	return open_path(vma->vmfd, do_open_reg_noseek_flags, &flags);
}

static void remap_get(struct file_desc *fdesc, char typ)
{
	struct reg_file_info *rfi;

	rfi = container_of(fdesc, struct reg_file_info, d);
	if (rfi->remap) {
		pr_debug("One more remap user (%c) for %s\n",
				typ, rfi->remap->rpath);
		/* No lock, we're still sngle-process here */
		rfi->remap->users++;
	}
}

static void collect_reg_fd(struct file_desc *fdesc,
		struct fdinfo_list_entry *fle, struct rst_info *ri)
{
	if (list_empty(&fdesc->fd_info_head))
		remap_get(fdesc, 'f');

	collect_gen_fd(fle, ri);
}

static int open_fe_fd(struct file_desc *fd)
{
	return open_path(fd, do_open_reg, NULL);
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
	.collect_fd = collect_reg_fd,
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

	remap_get(fdesc, 's');
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
	rfi->size_checked = false;

	pr_info("Collected [%s] ID %#x\n", rfi->path, rfi->rfe->id);
	return file_desc_add(&rfi->d, rfi->rfe->id, &reg_desc_ops);
}

static struct collect_image_info reg_file_cinfo = {
	.fd_type = CR_FD_REG_FILES,
	.pb_type = PB_REG_FILE,
	.priv_size = sizeof(struct reg_file_info),
	.collect = collect_one_regfile,
	.flags = COLLECT_SHARED,
};

int prepare_shared_reg_files(void)
{
	ghost_file_mutex = shmalloc(sizeof(*ghost_file_mutex));
	if (!ghost_file_mutex)
		return -1;

	mutex_init(ghost_file_mutex);
	return 0;
}

int collect_remaps_and_regfiles(void)
{
	if (collect_image(&reg_file_cinfo))
		return -1;

	if (collect_image(&remap_cinfo))
		return -1;

	return 0;
}
