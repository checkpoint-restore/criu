#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "cr_options.h"
#include "imgset.h"
#include "files.h"
#include "fs-magic.h"
#include "kerndat.h"
#include "image.h"
#include "mount.h"
#include "proc_parse.h"
#include "servicefd.h"
#include "file-lock.h"
#include "parasite.h"
#include "parasite-syscall.h"

struct file_lock_rst {
	FileLockEntry *fle;
	struct list_head l;
};

struct list_head file_lock_list = LIST_HEAD_INIT(file_lock_list);

static int collect_one_file_lock(void *o, ProtobufCMessage *m, struct cr_img *i)
{
	struct file_lock_rst *lr = o;

	lr->fle = pb_msg(m, FileLockEntry);
	list_add_tail(&lr->l, &file_lock_list);

	return 0;
}

struct collect_image_info file_locks_cinfo = {
	.fd_type = CR_FD_FILE_LOCKS,
	.pb_type = PB_FILE_LOCK,
	.priv_size = sizeof(struct file_lock_rst),
	.collect = collect_one_file_lock,
};

struct file_lock *alloc_file_lock(void)
{
	struct file_lock *flock;

	flock = xzalloc(sizeof(*flock));
	if (!flock)
		return NULL;

	INIT_LIST_HEAD(&flock->list);
	flock->real_owner = -1;
	flock->owners_fd = -1;

	return flock;
}

void free_file_locks(void)
{
	struct file_lock *flock, *tmp;

	list_for_each_entry_safe(flock, tmp, &file_lock_list, list) {
		xfree(flock);
	}

	INIT_LIST_HEAD(&file_lock_list);
}

static int dump_one_file_lock(FileLockEntry *fle)
{
	pr_info("LOCK flag: %d,type: %d,pid: %d,fd: %d,start: %8"PRIx64",len: %8"PRIx64"\n",
		fle->flag, fle->type, fle->pid,	fle->fd, fle->start, fle->len);

	return pb_write_one(img_from_set(glob_imgset, CR_FD_FILE_LOCKS),
			fle, PB_FILE_LOCK);
}

static void fill_flock_entry(FileLockEntry *fle, int fl_kind, int fl_ltype)
{
	fle->flag |= fl_kind;
	fle->type = fl_ltype;
}

int dump_file_locks(void)
{
	FileLockEntry	 fle;
	struct file_lock *fl;
	int	ret = 0;

	pr_info("Dumping file-locks\n");

	list_for_each_entry(fl, &file_lock_list, list) {
		if (fl->real_owner == -1) {
			if (fl->fl_kind == FL_POSIX) {
				pr_err("Unresolved lock found pid %d ino %ld\n",
						fl->fl_owner, fl->i_no);
				return -1;
			}

			continue;
		}

		file_lock_entry__init(&fle);
		fle.pid = fl->real_owner;
		fle.fd = fl->owners_fd;
		fill_flock_entry(&fle, fl->fl_kind, fl->fl_ltype);
		fle.start = fl->start;
		if (!strncmp(fl->end, "EOF", 3))
			fle.len = 0;
		else
			fle.len = (atoll(fl->end) + 1) - fl->start;

		ret = dump_one_file_lock(&fle);
		if (ret) {
			pr_err("Dump file lock failed!\n");
			goto err;
		}
	}

err:
	return ret;
}

static int lock_btrfs_file_match(pid_t pid, int fd, struct file_lock *fl, struct fd_parms *p)
{
	int phys_dev = MKKDEV(fl->maj, fl->min);
	char link[PATH_MAX], t[32];
	struct ns_id *ns;
	int ret;

	snprintf(t, sizeof(t), "/proc/%d/fd/%d", pid, fd);
	ret = readlink(t, link, sizeof(link)) - 1;
	if (ret < 0) {
		pr_perror("Can't read link of fd %d", fd);
		return -1;
	} else if ((size_t)ret == sizeof(link)) {
		pr_err("Buffer for read link of fd %d is too small\n", fd);
		return -1;
	}
	link[ret] = 0;

	ns = lookup_nsid_by_mnt_id(p->mnt_id);
	return  phys_stat_dev_match(p->stat.st_dev, phys_dev, ns, link);
}

static inline int lock_file_match(pid_t pid, int fd, struct file_lock *fl, struct fd_parms *p)
{
	dev_t dev = p->stat.st_dev;

	if (fl->i_no != p->stat.st_ino)
		return 0;

	/*
	 * Get the right devices for BTRFS. Look at phys_stat_resolve_dev()
	 * for more details.
	 */
	if (p->fs_type == BTRFS_SUPER_MAGIC) {
		if (p->mnt_id != -1) {
			struct mount_info *m;

			m = lookup_mnt_id(p->mnt_id);
			BUG_ON(m == NULL);
			dev = kdev_to_odev(m->s_dev);
		} else /* old kernel */
			return lock_btrfs_file_match(pid, fd, fl, p);
	}

	return makedev(fl->maj, fl->min) == dev;
}

static int lock_check_fd(int lfd, struct file_lock *fl)
{
	int ret;

	if (fl->fl_ltype & LOCK_MAND)
		ret = flock(lfd, LOCK_MAND | LOCK_RW);
	else
		ret = flock(lfd, LOCK_EX | LOCK_NB);
	pr_debug("   `- %d/%d\n", ret, errno);
	if (ret != 0) {
		if (errno != EAGAIN) {
			pr_err("Bogus lock test result %d\n", ret);
			return -1;
		}

		return 0;
	} else {
		/*
		 * The ret == 0 means, that new lock doesn't conflict
		 * with any others on the file. But since we do know, 
		 * that there should be some other one (file is found
		 * in /proc/locks), it means that the lock is already
		 * on file pointed by fd.
		 */
		pr_debug("   `- downgrading lock back\n");
		if (fl->fl_ltype & LOCK_MAND)
			flock(lfd, fl->fl_ltype);
		else if (fl->fl_ltype == F_RDLCK)
			flock(lfd, LOCK_SH);
	}

	return 1;
}

int note_file_lock(struct pid *pid, int fd, int lfd, struct fd_parms *p)
{
	struct file_lock *fl;
	int ret;

	if (kdat.has_fdinfo_lock)
		return 0;

	list_for_each_entry(fl, &file_lock_list, list) {
		ret = lock_file_match(pid->real, fd, fl, p);
		if (ret < 0)
			return -1;
		if (ret == 0)
			continue;

		if (!opts.handle_file_locks) {
			pr_err("Some file locks are hold by dumping tasks!"
					"You can try --" OPT_FILE_LOCKS " to dump them.\n");
			return -1;
		}

		if (fl->fl_kind == FL_POSIX) {
			/*
			 * POSIX locks cannot belong to anyone
			 * but creator.
			 */
			if (fl->fl_owner != pid->real)
				continue;
		} else /* fl->fl_kind == FL_FLOCK */ {
			int ret;

			/*
			 * FLOCKs can be inherited across fork,
			 * thus we can have any task as lock
			 * owner. But the creator is preferred
			 * anyway.
			 */

			if (fl->fl_owner != pid->real &&
					fl->real_owner != -1)
				continue;

			pr_debug("Checking lock holder %d:%d\n", pid->real, fd);
			ret = lock_check_fd(lfd, fl);
			if (ret < 0)
				return ret;
			if (ret == 0)
				continue;
		}

		fl->real_owner = pid->virt;
		fl->owners_fd = fd;

		pr_info("Found lock entry %d.%d %d vs %d\n",
				pid->real, pid->virt, fd,
				fl->fl_owner);
	}

	return 0;
}

static int restore_file_lock(FileLockEntry *fle)
{
	int ret = -1;
	unsigned int cmd;

	if (fle->flag & FL_FLOCK) {
		if (fle->type & LOCK_MAND) {
			cmd = fle->type;
		} else if (fle->type == F_RDLCK) {
			cmd = LOCK_SH;
		} else if (fle->type == F_WRLCK) {
			cmd = LOCK_EX;
		} else if (fle->type == F_UNLCK) {
			cmd = LOCK_UN;
		} else {
			pr_err("Unknown flock type!\n");
			goto err;
		}

		pr_info("(flock)flag: %d, type: %d, cmd: %d, pid: %d, fd: %d\n",
			fle->flag, fle->type, cmd, fle->pid, fle->fd);

		ret = flock(fle->fd, cmd);
		if (ret < 0) {
			pr_err("Can not set flock!\n");
			goto err;
		}
	} else if (fle->flag & FL_POSIX) {
		struct flock flk;
		memset(&flk, 0, sizeof(flk));

		flk.l_whence = SEEK_SET;
		flk.l_start  = fle->start;
		flk.l_len    = fle->len;
		flk.l_pid    = fle->pid;
		flk.l_type   = fle->type;

		pr_info("(posix)flag: %d, type: %d, pid: %d, fd: %d, "
			"start: %8"PRIx64", len: %8"PRIx64"\n",
			fle->flag, fle->type, fle->pid, fle->fd,
			fle->start, fle->len);

		ret = fcntl(fle->fd, F_SETLKW, &flk);
		if (ret < 0) {
			pr_err("Can not set posix lock!\n");
			goto err;
		}
	} else {
		pr_err("Unknown file lock style!\n");
		goto err;
	}

	return 0;
err:
	return ret;
}

static int restore_file_locks(int pid)
{
	int ret = 0;
	struct file_lock_rst *lr;

	list_for_each_entry(lr, &file_lock_list, l) {
		if (lr->fle->pid == pid) {
			ret = restore_file_lock(lr->fle);
			if (ret)
				break;
		}
	}

	return ret;
}

int prepare_file_locks(int pid)
{
	if (!opts.handle_file_locks)
		return 0;

	if (!(file_locks_cinfo.flags & COLLECT_HAPPENED)) {
		pr_warn("Per-pid file locks are deprecated\n");
		return -1;
	}

	return restore_file_locks(pid);

}
