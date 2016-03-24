#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <utime.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <aio.h>

#include <sys/fanotify.h>

#include "compiler.h"
#include "asm/types.h"
#include "imgset.h"
#include "fsnotify.h"
#include "proc_parse.h"
#include "mount.h"
#include "image.h"
#include "util.h"
#include "files.h"
#include "files-reg.h"
#include "file-ids.h"
#include "log.h"
#include "list.h"
#include "lock.h"
#include "irmap.h"
#include "cr_options.h"
#include "namespaces.h"
#include "pstree.h"
#include "fault-injection.h"

#include "protobuf.h"
#include "images/fsnotify.pb-c.h"
#include "images/mnt.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "fsnotify: "

struct fsnotify_mark_info {
	struct list_head		list;
	union {
		InotifyWdEntry		*iwe;
		FanotifyMarkEntry	*fme;
	};
	struct file_remap		*remap;
};

struct fsnotify_file_info {
	struct list_head		list;
	union {
		InotifyFileEntry	*ife;
		FanotifyFileEntry	*ffe;
	};
	struct list_head		marks;
	struct file_desc		d;
};

/* File handle */
typedef struct {
	u32 bytes;
	u32 type;
	u64 __handle[16];
} fh_t;

static LIST_HEAD(inotify_info_head);
static LIST_HEAD(fanotify_info_head);

/* Checks if file descriptor @lfd is inotify */
int is_inotify_link(char *link)
{
	return is_anon_link_type(link, "inotify");
}

/* Checks if file descriptor @lfd is fanotify */
int is_fanotify_link(char *link)
{
	return is_anon_link_type(link, "[fanotify]");
}

static void decode_handle(fh_t *handle, FhEntry *img)
{
	memzero(handle, sizeof(*handle));

	handle->type	= img->type;
	handle->bytes	= img->bytes;

	memcpy(handle->__handle, img->handle,
			min(pb_repeated_size(img, handle),
				sizeof(handle->__handle)));
}

static int open_by_handle(void *arg, int fd, int pid)
{
	return open_by_handle_at(fd, arg, O_PATH);
}

static char *alloc_openable(unsigned int s_dev, unsigned long i_ino, FhEntry *f_handle)
{
	struct mount_info *m;
	fh_t handle;
	int fd = -1;
	char *path;

	decode_handle(&handle, f_handle);

	/*
	 * We gonna try to open the handle and then
	 * depending on command line options and type
	 * of the filesystem (tmpfs/devtmpfs do not
	 * preserve their inodes between mounts) we
	 * might need to find out an openable path
	 * get used on restore as a watch destination.
	 */
	for (m = mntinfo; m; m = m->next) {
		char buf[PATH_MAX], *__path;
		int mntfd, openable_fd;
		struct stat st;

		if (m->s_dev != s_dev)
			continue;

		mntfd = __open_mountpoint(m, -1);
		pr_debug("\t\tTrying via mntid %d root %s ns_mountpoint @%s (%d)\n",
			 m->mnt_id, m->root, m->ns_mountpoint, mntfd);
		if (mntfd < 0)
			continue;

		fd = userns_call(open_by_handle, UNS_FDOUT, &handle,
				 sizeof(handle), mntfd);
		close(mntfd);
		if (fd < 0)
			continue;

		if (read_fd_link(fd, buf, sizeof(buf)) < 0) {
			close(fd);
			goto err;
		}
		close(fd);

		/*
		 * Convert into a relative path.
		 */
		__path = (buf[1] != '\0') ? buf + 1 : ".";
		pr_debug("\t\t\tlink as %s\n", __path);

		mntfd = mntns_get_root_fd(m->nsid);
		if (mntfd < 0)
			goto err;

		openable_fd = openat(mntfd, __path, O_PATH);
		if (openable_fd >= 0) {
			if (fstat(openable_fd, &st)) {
				pr_perror("Can't stat on %s\n", __path);
				close(openable_fd);
				return ERR_PTR(-errno);
			}
			close(openable_fd);

			pr_debug("\t\t\topenable (inode %s) as %s\n",
				 st.st_ino == i_ino ?
				 "match" : "don't match", __path);

			if (st.st_ino == i_ino) {
				path = xstrdup(buf);
				if (path == NULL)
					goto err;

				f_handle->has_mnt_id = true;
				f_handle->mnt_id = m->mnt_id;
				return path;
			}
		} else
			pr_debug("\t\t\tnot openable as %s (%m)\n", __path);
	}

	return ERR_PTR(-ENOENT);
err:
	return ERR_PTR(-1);
}

static int open_handle(unsigned int s_dev, unsigned long i_ino,
		FhEntry *f_handle)
{
	int mntfd, fd = -1;
	fh_t handle;

	decode_handle(&handle, f_handle);

	pr_debug("Opening fhandle %x:%Lx...\n",
			s_dev, (unsigned long long)handle.__handle[0]);

	mntfd = open_mount(s_dev);
	if (mntfd < 0) {
		pr_err("Mount root for 0x%08x not found\n", s_dev);
		goto out;
	}

	fd = userns_call(open_by_handle, UNS_FDOUT, &handle, sizeof(handle), mntfd);
	if (fd < 0) {
		pr_perror("Can't open file handle for 0x%08x:0x%016lx",
				s_dev, i_ino);
	}

	close(mntfd);
out:
	return fd;
}

int check_open_handle(unsigned int s_dev, unsigned long i_ino,
		FhEntry *f_handle)
{
	int fd = -1;
	char *path;

	if (fault_injected(FI_CHECK_OPEN_HANDLE)) {
		fd = -1;
		goto fault;
	}

	fd = open_handle(s_dev, i_ino, f_handle);
fault:
	if (fd >= 0) {
		struct mount_info *mi;

		pr_debug("\tHandle 0x%x:0x%lx is openable\n", s_dev, i_ino);

		mi = lookup_mnt_sdev(s_dev);
		if (mi == NULL) {
			pr_err("Unable to lookup a mount by dev 0x%x\n", s_dev);
			goto err;
		}

		/*
		 * Always try to fetch watchee path first. There are several reasons:
		 *
		 *  - tmpfs/devtmps do not save inode numbers between mounts,
		 *    so it is critical to have the complete path under our
		 *    hands for restore purpose;
		 *
		 *  - in case of migration the inodes might be changed as well
		 *    so the only portable solution is to carry the whole path
		 *    to the watchee inside image.
		 */
		path = alloc_openable(s_dev, i_ino, f_handle);
		if (!IS_ERR_OR_NULL(path))
			goto out;

		if ((mi->fstype->code == FSTYPE__TMPFS) ||
		    (mi->fstype->code == FSTYPE__DEVTMPFS)) {
			pr_err("Can't find suitable path for handle (dev %#x ino %#lx): %d\n",
			       s_dev, i_ino, (int)PTR_ERR(path));
			goto err;
		}

		if (!opts.force_irmap)
			/*
			 * If we're not forced to do irmap, then
			 * say we have no path for watch. Otherwise
			 * do irmap scan even if the handle is
			 * working.
			 *
			 * FIXME -- no need to open-by-handle if
			 * we are in force-irmap and not on tempfs
			 */
			goto out_nopath;
	}

	pr_warn("\tHandle 0x%x:0x%lx cannot be opened\n", s_dev, i_ino);
	path = irmap_lookup(s_dev, i_ino);
	if (!path) {
		pr_err("\tCan't dump that handle\n");
		return -1;
	}
out:
	pr_debug("\tDumping %s as path for handle\n", path);
	f_handle->path = path;
out_nopath:
	close_safe(&fd);
	return 0;
err:
	close_safe(&fd);
	return -1;
}

struct watch_list {
	struct fsnotify_params fsn_params;
	struct list_head list;
	int n;
};

static int dump_inotify_entry(union fdinfo_entries *e, void *arg)
{
	struct watch_list *wd_list = (struct watch_list *) arg;
	struct inotify_wd_entry *wd_entry = (struct inotify_wd_entry *) e;
	InotifyWdEntry *we = &wd_entry->e;

	pr_info("wd: wd 0x%08x s_dev 0x%08x i_ino 0x%16"PRIx64" mask 0x%08x\n",
			we->wd, we->s_dev, we->i_ino, we->mask);
	pr_info("\t[fhandle] bytes 0x%08x type 0x%08x __handle 0x%016"PRIx64":0x%016"PRIx64"\n",
			we->f_handle->bytes, we->f_handle->type,
			we->f_handle->handle[0], we->f_handle->handle[1]);

	if (we->mask & KERNEL_FS_EVENT_ON_CHILD)
		pr_warn_once("\t\tDetected FS_EVENT_ON_CHILD bit "
			     "in mask (will be ignored on restore)\n");

	if (check_open_handle(we->s_dev, we->i_ino, we->f_handle)) {
		free_inotify_wd_entry(e);
		return -1;
	}

	list_add_tail(&wd_entry->node, &wd_list->list);
	wd_list->n++;

	return 0;
}

static int dump_one_inotify(int lfd, u32 id, const struct fd_parms *p)
{
	struct watch_list wd_list = {.list = LIST_HEAD_INIT(wd_list.list), .n = 0};
	InotifyFileEntry ie = INOTIFY_FILE_ENTRY__INIT;
	union fdinfo_entries *we, *tmp;
	int exit_code = -1, i, ret;

	ret = fd_has_data(lfd);
	if (ret < 0)
		return -1;
	else if (ret > 0)
		pr_warn("The 0x%08x inotify events will be dropped\n", id);

	ie.id = id;
	ie.flags = p->flags;
	ie.fown = (FownEntry *)&p->fown;

	if (parse_fdinfo(lfd, FD_TYPES__INOTIFY, dump_inotify_entry, &wd_list))
		goto free;

	ie.wd = xmalloc(sizeof(*ie.wd) * wd_list.n);
	if (!ie.wd)
		goto free;

	i = 0;
	list_for_each_entry(we, &wd_list.list, ify.node)
		ie.wd[i++] = &we->ify.e;
	ie.n_wd = wd_list.n;

	pr_info("id 0x%08x flags 0x%08x\n", ie.id, ie.flags);
	if (pb_write_one(img_from_set(glob_imgset, CR_FD_INOTIFY_FILE), &ie, PB_INOTIFY_FILE))
		goto free;

	exit_code = 0;
free:
	xfree(ie.wd);
	list_for_each_entry_safe(we, tmp, &wd_list.list, ify.node)
		free_inotify_wd_entry(we);

	return exit_code;
}

static int pre_dump_inotify_entry(union fdinfo_entries *e, void *arg)
{
	InotifyWdEntry *we = &e->ify.e;
	int ret;

	ret = irmap_queue_cache(we->s_dev, we->i_ino, we->f_handle);
	free_inotify_wd_entry(e);

	return ret;
}

static int pre_dump_one_inotify(int pid, int lfd)
{
	return parse_fdinfo_pid(pid, lfd, FD_TYPES__INOTIFY, pre_dump_inotify_entry, NULL);
}

const struct fdtype_ops inotify_dump_ops = {
	.type		= FD_TYPES__INOTIFY,
	.dump		= dump_one_inotify,
	.pre_dump	= pre_dump_one_inotify,
};

static int dump_fanotify_entry(union fdinfo_entries *e, void *arg)
{
	struct watch_list *wd_list = (struct watch_list *) arg;
	FanotifyMarkEntry *fme = &e->ffy.e;

	if (fme->type == MARK_TYPE__INODE) {

		BUG_ON(!fme->ie);

		pr_info("mark: s_dev 0x%08x i_ino 0x%016"PRIx64" mask 0x%08x\n",
			fme->s_dev, fme->ie->i_ino, fme->mask);

		pr_info("\t[fhandle] bytes 0x%08x type 0x%08x __handle 0x%016"PRIx64":0x%016"PRIx64"\n",
			fme->ie->f_handle->bytes, fme->ie->f_handle->type,
			fme->ie->f_handle->handle[0], fme->ie->f_handle->handle[1]);

		if (check_open_handle(fme->s_dev, fme->ie->i_ino, fme->ie->f_handle))
			goto out;
	}

	if (fme->type == MARK_TYPE__MOUNT) {
		struct mount_info *m;

		BUG_ON(!fme->me);

		m = lookup_mnt_id(fme->me->mnt_id);
		if (!m) {
			pr_err("Can't find mnt_id 0x%x\n", fme->me->mnt_id);
			goto out;
		}
		fme->s_dev = m->s_dev;

		pr_info("mark: s_dev 0x%08x mnt_id  0x%08x mask 0x%08x\n",
			fme->s_dev, fme->me->mnt_id, fme->mask);

	}

	list_add_tail(&e->ffy.node, &wd_list->list);
	wd_list->n++;

	return 0;
out:
	free_fanotify_mark_entry(e);
	return -1;
}

static int dump_one_fanotify(int lfd, u32 id, const struct fd_parms *p)
{
	struct watch_list wd_list = {.list = LIST_HEAD_INIT(wd_list.list), .n = 0};
	FanotifyFileEntry fe = FANOTIFY_FILE_ENTRY__INIT;
	union fdinfo_entries *we, *tmp;
	int ret = -1, i;

	ret = fd_has_data(lfd);
	if (ret < 0)
		return -1;
	else if (ret > 0)
		pr_warn("The 0x%08x fanotify events will be dropped\n", id);
	ret = -1;

	fe.id = id;
	fe.flags = p->flags;
	fe.fown = (FownEntry *)&p->fown;

	if (parse_fdinfo(lfd, FD_TYPES__FANOTIFY,
			 dump_fanotify_entry, &wd_list) < 0)
		goto free;

	fe.mark = xmalloc(sizeof(*fe.mark) * wd_list.n);
	if (!fe.mark)
		goto free;

	i = 0;
	list_for_each_entry(we, &wd_list.list, ify.node)
		fe.mark[i++] = &we->ffy.e;
	fe.n_mark = wd_list.n;

	pr_info("id 0x%08x flags 0x%08x\n", fe.id, fe.flags);

	fe.faflags = wd_list.fsn_params.faflags;
	fe.evflags = wd_list.fsn_params.evflags;

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_FANOTIFY_FILE), &fe, PB_FANOTIFY_FILE);
free:
	xfree(fe.mark);
	list_for_each_entry_safe(we, tmp, &wd_list.list, ify.node)
		free_fanotify_mark_entry(we);
	return ret;
}

static int pre_dump_fanotify_entry(union fdinfo_entries *e, void *arg)
{
	FanotifyMarkEntry *fme = &e->ffy.e;
	int ret = 0;

	if (fme->type == MARK_TYPE__INODE)
		ret = irmap_queue_cache(fme->s_dev, fme->ie->i_ino,
				fme->ie->f_handle);

	free_fanotify_mark_entry(e);
	return ret;
}

static int pre_dump_one_fanotify(int pid, int lfd)
{
	struct fsnotify_params fsn_params = { };
	return parse_fdinfo_pid(pid, lfd, FD_TYPES__FANOTIFY, pre_dump_fanotify_entry, &fsn_params);
}

const struct fdtype_ops fanotify_dump_ops = {
	.type		= FD_TYPES__FANOTIFY,
	.dump		= dump_one_fanotify,
	.pre_dump	= pre_dump_one_fanotify,
};

static char *get_mark_path(const char *who, struct file_remap *remap,
			   FhEntry *f_handle, unsigned long i_ino,
			   unsigned int s_dev, char *buf, int *target)
{
	char *path = NULL;

	if (remap) {
		int mntns_root;

		mntns_root = mntns_get_root_by_mnt_id(remap->rmnt_id);

		pr_debug("\t\tRestore %s watch for 0x%08x:0x%016lx (via %s)\n",
			 who, s_dev, i_ino, remap->rpath);
		*target = openat(mntns_root, remap->rpath, O_PATH);
	} else if (f_handle->path) {
		int  mntns_root;
		char *path = ".";
		uint32_t mnt_id = f_handle->has_mnt_id ? f_handle->mnt_id : -1;


		/* irmap cache is collected in the root namespaces. */
		mntns_root = mntns_get_root_by_mnt_id(mnt_id);

		/* change "/foo" into "foo" and "/" into "." */
		if (f_handle->path[1] != '\0')
			path = f_handle->path + 1;

		pr_debug("\t\tRestore with path hint %d:%s\n", mnt_id, path);
		*target = openat(mntns_root, path, O_PATH);
	} else
		*target = open_handle(s_dev, i_ino, f_handle);

	if (*target < 0) {
		pr_perror("Unable to open %s", f_handle->path);
		goto err;
	}

	/*
	 * fanotify/inotify open syscalls want path to attach
	 * watch to. But the only thing we have is an FD obtained
	 * via fhandle. Fortunatelly, when trying to attach the
	 * /proc/pid/fd/ link, we will watch the inode the link
	 * points to, i.e. -- just what we want.
	 */

	sprintf(buf, "/proc/self/fd/%d", *target);
	path = buf;

	if (!pr_quelled(LOG_DEBUG)) {
		char link[PATH_MAX];

		if (read_fd_link(*target, link, sizeof(link)) < 0)
			link[0] = '\0';

		pr_debug("\t\tRestore %s watch for 0x%08x:0x%016lx (via %s -> %s)\n",
				who, s_dev, i_ino, path, link);
	}
err:
	return path;
}

static int restore_one_inotify(int inotify_fd, struct fsnotify_mark_info *info)
{
	InotifyWdEntry *iwe = info->iwe;
	int ret = -1, target = -1;
	char buf[PSFDS], *path;

	path = get_mark_path("inotify", info->remap, iwe->f_handle,
			     iwe->i_ino, iwe->s_dev, buf, &target);
	if (!path)
		goto err;

	/*
	 * FIXME The kernel allocates wd-s sequentially,
	 * this is suboptimal, but the kernel doesn't
	 * provide and API for this yet :(
	 */
	while (1) {
		int wd;

		wd = inotify_add_watch(inotify_fd, path, iwe->mask);
		if (wd < 0) {
			pr_perror("Can't add watch for 0x%x with 0x%x", inotify_fd, iwe->wd);
			break;
		} else if (wd == iwe->wd) {
			ret = 0;
			break;
		} else if (wd > iwe->wd) {
			pr_err("Unsorted watch 0x%x found for 0x%x with 0x%x\n", wd, inotify_fd, iwe->wd);
			break;
		}

		pr_debug("\t\tWatch got 0x%x but 0x%x expected\n", wd, iwe->wd);
		inotify_rm_watch(inotify_fd, wd);
	}

err:
	if (info->remap)
		remap_put(info->remap);

	close_safe(&target);
	return ret;
}

static int restore_one_fanotify(int fd, struct fsnotify_mark_info *mark)
{
	FanotifyMarkEntry *fme = mark->fme;
	unsigned int flags = FAN_MARK_ADD;
	int ret = -1, target = -1;
	char buf[PSFDS], *path = NULL;

	if (fme->type == MARK_TYPE__MOUNT) {
		struct mount_info *m;
		int mntns_root;

		m = lookup_mnt_id(fme->me->mnt_id);
		if (!m) {
			pr_err("Can't find mount mnt_id 0x%x\n", fme->me->mnt_id);
			return -1;
		}

		mntns_root = mntns_get_root_fd(m->nsid);

		target = openat(mntns_root, m->ns_mountpoint, O_PATH);
		if (target == -1) {
			pr_perror("Unable to open %s", m->ns_mountpoint);
			goto err;
		}

		flags |= FAN_MARK_MOUNT;
		snprintf(buf, sizeof(buf), "/proc/self/fd/%d", target);
		path = buf;
	} else if (fme->type == MARK_TYPE__INODE) {
		path = get_mark_path("fanotify", mark->remap,
				     fme->ie->f_handle, fme->ie->i_ino,
				     fme->s_dev, buf, &target);
		if (!path)
			goto err;
	} else {
		pr_err("Bad fsnotify mark type 0x%x\n", fme->type);
		goto err;
	}

	flags |= fme->mflags;

	if (mark->fme->mask) {
		ret = fanotify_mark(fd, flags, fme->mask, AT_FDCWD, path);
		if (ret) {
			pr_err("Adding fanotify mask 0x%x on 0x%x/%s failed (%d)\n",
			       fme->mask, fme->id, path, ret);
			goto err;
		}
	}

	if (fme->ignored_mask) {
		ret = fanotify_mark(fd, flags | FAN_MARK_IGNORED_MASK,
				    fme->ignored_mask, AT_FDCWD, path);
		if (ret) {
			pr_err("Adding fanotify ignored-mask 0x%x on 0x%x/%s failed (%d)\n",
			       fme->ignored_mask, fme->id, path, ret);
			goto err;
		}
	}

	if (mark->remap)
		remap_put(mark->remap);

err:
	close_safe(&target);
	return ret;
}

static int open_inotify_fd(struct file_desc *d)
{
	struct fsnotify_file_info *info;
	struct fsnotify_mark_info *wd_info;
	int tmp;

	info = container_of(d, struct fsnotify_file_info, d);

	tmp = inotify_init1(info->ife->flags);
	if (tmp < 0) {
		pr_perror("Can't create inotify for 0x%08x", info->ife->id);
		return -1;
	}

	list_for_each_entry(wd_info, &info->marks, list) {
		pr_info("\tRestore 0x%x wd for 0x%08x\n", wd_info->iwe->wd, wd_info->iwe->id);
		if (restore_one_inotify(tmp, wd_info)) {
			close_safe(&tmp);
			break;
		}
	}

	if (restore_fown(tmp, info->ife->fown))
		close_safe(&tmp);

	return tmp;
}

static int open_fanotify_fd(struct file_desc *d)
{
	struct fsnotify_file_info *info;
	struct fsnotify_mark_info *mark;
	unsigned int flags = 0;
	int ret;

	info = container_of(d, struct fsnotify_file_info, d);

	flags = info->ffe->faflags;
	if (info->ffe->flags & O_CLOEXEC)
		flags |= FAN_CLOEXEC;
	if (info->ffe->flags & O_NONBLOCK)
		flags |= FAN_NONBLOCK;

	ret = fanotify_init(flags, info->ffe->evflags);
	if (ret < 0) {
		pr_perror("Can't init fanotify mark (%d)", ret);
		return -1;
	}

	list_for_each_entry(mark, &info->marks, list) {
		pr_info("\tRestore fanotify for 0x%08x\n", mark->fme->id);
		if (restore_one_fanotify(ret, mark)) {
			close_safe(&ret);
			break;
		}
	}

	if (restore_fown(ret, info->ffe->fown))
		close_safe(&ret);

	return ret;
}

static struct file_desc_ops inotify_desc_ops = {
	.type = FD_TYPES__INOTIFY,
	.open = open_inotify_fd,
};

static struct file_desc_ops fanotify_desc_ops = {
	.type = FD_TYPES__FANOTIFY,
	.open = open_fanotify_fd,
};

static struct fsnotify_file_info *find_inotify_info(unsigned id)
{
	struct fsnotify_file_info *p;
	static struct fsnotify_file_info *last = NULL;

	if (last && last->ife->id == id) {
		/*
		 * An optimization for clean dump image -- criu puts
		 * wd-s for one inotify in one row, thus sometimes
		 * we can avoid scanning the inotify_info_head.
		 */
		pr_debug("\t\tlast ify for 0x%08x found\n", id);
		return last;
	}

	list_for_each_entry(p, &inotify_info_head, list)
		if (p->ife->id == id) {
			last = p;
			return p;
		}

	pr_err("Can't find inotify with id 0x%08x\n", id);
	return NULL;
}

static int __collect_inotify_mark(struct fsnotify_file_info *p, struct fsnotify_mark_info *mark)
{
	struct fsnotify_mark_info *m;

	/*
	 * We should put marks in wd ascending order. See comment
	 * in restore_one_inotify() for explanation.
	 */
	list_for_each_entry(m, &p->marks, list)
		if (m->iwe->wd > mark->iwe->wd)
			break;

	list_add_tail(&mark->list, &m->list);
	mark->remap = lookup_ghost_remap(mark->iwe->s_dev, mark->iwe->i_ino);
	return 0;
}

static int collect_inotify_mark(struct fsnotify_mark_info *mark)
{
	struct fsnotify_file_info *p;

	p = find_inotify_info(mark->iwe->id);
	if (!p)
		return -1;

	return __collect_inotify_mark(p, mark);
}

static int __collect_fanotify_mark(struct fsnotify_file_info *p,
				struct fsnotify_mark_info *mark)
{
	list_add(&mark->list, &p->marks);
	if (mark->fme->type == MARK_TYPE__INODE)
		mark->remap = lookup_ghost_remap(mark->fme->s_dev,
						 mark->fme->ie->i_ino);
	return 0;
}

static int collect_fanotify_mark(struct fsnotify_mark_info *mark)
{
	struct fsnotify_file_info *p;

	list_for_each_entry(p, &fanotify_info_head, list) {
		if (p->ffe->id == mark->fme->id)
			return __collect_inotify_mark(p, mark);
	}

	pr_err("Can't find fanotify with id 0x%08x\n", mark->fme->id);
	return -1;
}

static int collect_one_inotify(void *o, ProtobufCMessage *msg, struct cr_img *img)
{
	struct fsnotify_file_info *info = o;
	int i;

	info->ife = pb_msg(msg, InotifyFileEntry);
	INIT_LIST_HEAD(&info->marks);
	list_add(&info->list, &inotify_info_head);
	pr_info("Collected id 0x%08x flags 0x%08x\n", info->ife->id, info->ife->flags);

	for (i = 0; i < info->ife->n_wd; i++) {
		struct fsnotify_mark_info *mark;

		mark = xmalloc(sizeof(*mark));
		if (!mark)
			return -1;

		mark->iwe = info->ife->wd[i];
		INIT_LIST_HEAD(&mark->list);
		mark->remap = NULL;

		if (__collect_inotify_mark(info, mark))
			return -1;
	}

	return file_desc_add(&info->d, info->ife->id, &inotify_desc_ops);
}

struct collect_image_info inotify_cinfo = {
	.fd_type	= CR_FD_INOTIFY_FILE,
	.pb_type	= PB_INOTIFY_FILE,
	.priv_size	= sizeof(struct fsnotify_file_info),
	.collect	= collect_one_inotify,
};

static int collect_one_fanotify(void *o, ProtobufCMessage *msg, struct cr_img *img)
{
	struct fsnotify_file_info *info = o;
	int i;

	info->ffe = pb_msg(msg, FanotifyFileEntry);
	INIT_LIST_HEAD(&info->marks);
	list_add(&info->list, &fanotify_info_head);
	pr_info("Collected id 0x%08x flags 0x%08x\n", info->ffe->id, info->ffe->flags);

	for (i = 0; i < info->ffe->n_mark; i++) {
		struct fsnotify_mark_info *mark;

		mark = xmalloc(sizeof(*mark));
		if (!mark)
			return -1;

		mark->fme = info->ffe->mark[i];
		INIT_LIST_HEAD(&mark->list);
		mark->remap = NULL;

		if (__collect_fanotify_mark(info, mark))
			return -1;
	}

	return file_desc_add(&info->d, info->ffe->id, &fanotify_desc_ops);
}

struct collect_image_info fanotify_cinfo = {
	.fd_type	= CR_FD_FANOTIFY_FILE,
	.pb_type	= PB_FANOTIFY_FILE,
	.priv_size	= sizeof(struct fsnotify_file_info),
	.collect	= collect_one_fanotify,
};

static int collect_one_inotify_mark(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct fsnotify_mark_info *mark = o;

	mark->iwe = pb_msg(msg, InotifyWdEntry);
	INIT_LIST_HEAD(&mark->list);
	mark->remap = NULL;

	/*
	 * The kernel prior 4.3 might export internal event
	 * mask bits which are not part of user-space API. It
	 * is fixed in kernel but we have to keep backward
	 * compatibility with old images. So mask out
	 * inappropriate bits (in particular fdinfo might
	 * have FS_EVENT_ON_CHILD bit set).
	 */
	mark->iwe->mask &= ~KERNEL_FS_EVENT_ON_CHILD;

	return collect_inotify_mark(mark);
}

struct collect_image_info inotify_mark_cinfo = {
	.fd_type	= CR_FD_INOTIFY_WD,
	.pb_type	= PB_INOTIFY_WD,
	.priv_size	= sizeof(struct fsnotify_mark_info),
	.collect	= collect_one_inotify_mark,
};

static int collect_one_fanotify_mark(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct fsnotify_mark_info *mark = o;

	mark->fme = pb_msg(msg, FanotifyMarkEntry);
	INIT_LIST_HEAD(&mark->list);
	mark->remap = NULL;

	return collect_fanotify_mark(mark);
}

struct collect_image_info fanotify_mark_cinfo = {
	.fd_type	= CR_FD_FANOTIFY_MARK,
	.pb_type	= PB_FANOTIFY_MARK,
	.priv_size	= sizeof(struct fsnotify_mark_info),
	.collect	= collect_one_fanotify_mark,
};
