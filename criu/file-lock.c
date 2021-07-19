#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/file.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fsuid.h>
#include <sys/sysmacros.h>

#include "cr_options.h"
#include "imgset.h"
#include "files.h"
#include "fs-magic.h"
#include "kerndat.h"
#include "image.h"
#include "util.h"
#include "mount.h"
#include "proc_parse.h"
#include "servicefd.h"
#include "file-lock.h"
#include "pstree.h"
#include "files-reg.h"

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
	flock->fl_holder = -1;

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
	pr_info("LOCK flag: %d,type: %d,pid: %d,fd: %d,start: %8" PRIx64 ",len: %8" PRIx64 "\n", fle->flag, fle->type,
		fle->pid, fle->fd, fle->start, fle->len);

	return pb_write_one(img_from_set(glob_imgset, CR_FD_FILE_LOCKS), fle, PB_FILE_LOCK);
}

static void fill_flock_entry(FileLockEntry *fle, int fl_kind, int fl_ltype)
{
	fle->flag |= fl_kind;
	fle->type = fl_ltype;
}

int dump_file_locks(void)
{
	FileLockEntry fle;
	struct file_lock *fl;
	int ret = 0;

	pr_info("Dumping file-locks\n");

	list_for_each_entry(fl, &file_lock_list, list) {
		if (fl->real_owner == -1) {
			if (fl->fl_kind == FL_POSIX) {
				pr_err("Unresolved lock found pid %d ino %ld\n", fl->fl_owner, fl->i_no);
				return -1;
			}

			continue;
		}

		if (!opts.handle_file_locks) {
			pr_err("Some file locks are hold by dumping tasks! "
			       "You can try --" OPT_FILE_LOCKS " to dump them.\n");
			return -1;
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
	return phys_stat_dev_match(p->stat.st_dev, phys_dev, ns, link);
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
			ret = flock(lfd, fl->fl_ltype);
		else if (fl->fl_ltype == F_RDLCK)
			ret = flock(lfd, LOCK_SH);
		if (ret) {
			pr_err("Can't downgrade lock back %d\n", ret);
			return -1;
		}
	}

	return 1;
}

static int lock_ofd_check_fd(int lfd, struct file_lock *fl)
{
	int ret;

	struct flock lck = { .l_whence = SEEK_SET, .l_type = F_WRLCK, .l_start = fl->start };
	if (strcmp(fl->end, "EOF")) {
		unsigned long end;

		ret = sscanf(fl->end, "%lu", &end);
		if (ret <= 0) {
			pr_err("Invalid lock entry\n");
			return -1;
		}
		lck.l_len = end - fl->start + 1;
	} else {
		lck.l_len = 0;
	}

	ret = fcntl(lfd, F_OFD_SETLK, &lck);
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
		if (fl->fl_ltype & LOCK_WRITE)
			lck.l_type = F_WRLCK;
		else
			lck.l_type = F_RDLCK;

		ret = fcntl(lfd, F_OFD_SETLK, &lck);
		if (ret) {
			pr_err("Can't downgrade lock back %d\n", ret);
			return -1;
		}
	}

	return 1;
}

static int lease_check_fd(int fd, int file_flags, struct file_lock *fl)
{
	int file_lease_type, err;
	int lease_type = fl->fl_ltype & (~LEASE_BREAKING);

	if ((file_flags & O_ACCMODE) != O_RDONLY) {
		/*
		 * Write OFD conflicts with any lease not associated
		 * with it, therefore there is can't be other lease
		 * or OFD for this file.
		 */
		return 1;
	}

	file_lease_type = fcntl(fd, F_GETLEASE);
	if (file_lease_type < 0) {
		pr_err("Can't get lease type\n");
		return -1;
	}

	/*
	 * Only read OFDs can be present for the file. If
	 * read and write OFDs with at least one lease had
	 * presented, it would have conflicted.
	 */
	if (fl->fl_ltype & LEASE_BREAKING) {
		/*
		 * Only read leases are possible for read OFDs
		 * and they all should be in breaking state,
		 * because the current one is.
		 */
		int compatible_type = file_lease_type;

		if (compatible_type != F_UNLCK) {
			pr_err("Lease doesn't conflicts but breaks\n");
			return -1;
		}
		/*
		 * Due to activated breaking sequence we can't
		 * get actual lease type with F_GETLEASE.
		 * The err == 0 after lease upgrade means, that
		 * there is already read lease on OFD. Otherwise
		 * it would fail, because current read lease is
		 * still set and breaking.
		 */
		err = fcntl(fd, F_SETLEASE, F_RDLCK);
		if (err < 0) {
			if (errno != EAGAIN) {
				pr_perror("Can't set lease (fd %i)", fd);
				return -1;
			}
			return 0;
		}
		return 1;
	} else {
		/*
		 * The file can have only non-breaking read
		 * leases, because otherwise the current one
		 * also would have broke.
		 */
		if (lease_type != F_RDLCK) {
			pr_err("Incorrect lease type\n");
			return -1;
		}

		if (file_lease_type == F_UNLCK)
			return 0;
		if (file_lease_type == F_RDLCK)
			return 1;
		pr_err("Invalid file lease type\n");
		return -1;
	}
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
		} else if (fl->fl_kind == FL_LEASE) {
			if (fl->owners_fd >= 0)
				continue;
			if (fl->fl_owner != pid->real && fl->real_owner != -1)
				continue;

			ret = lease_check_fd(lfd, p->flags, fl);
			if (ret < 0)
				return ret;
			if (ret == 0)
				continue;
		} else /* fl->fl_kind == FL_FLOCK || fl->fl_kind == FL_OFD */ {
			int ret;

			/*
			 * OFD locks & FLOCKs can be inherited across fork,
			 * thus we can have any task as lock
			 * owner. But the creator is preferred
			 * anyway.
			 */

			if (fl->fl_owner != pid->real && fl->real_owner != -1)
				continue;

			pr_debug("Checking lock holder %d:%d\n", pid->real, fd);
			if (fl->fl_kind == FL_FLOCK)
				ret = lock_check_fd(lfd, fl);
			else
				ret = lock_ofd_check_fd(lfd, fl);

			if (ret < 0)
				return ret;
			if (ret == 0)
				continue;
		}

		fl->fl_holder = pid->real;
		fl->real_owner = pid->ns[0].virt;
		fl->owners_fd = fd;

		pr_info("Found lock entry %d.%d %d vs %d\n", pid->real, pid->ns[0].virt, fd, fl->fl_owner);
	}

	return 0;
}

void discard_dup_locks_tail(pid_t pid, int fd)
{
	struct file_lock *fl, *p;

	list_for_each_entry_safe_reverse(fl, p, &file_lock_list, list) {
		if (fl->owners_fd != fd || pid != fl->fl_holder)
			break;

		list_del(&fl->list);
		xfree(fl);
	}
}

int correct_file_leases_type(struct pid *pid, int fd, int lfd)
{
	struct file_lock *fl;
	int target_type;

	list_for_each_entry(fl, &file_lock_list, list) {
		/* owners_fd should be set before usage */
		if (fl->fl_holder != pid->real || fl->owners_fd != fd)
			continue;

		if (fl->fl_kind == FL_LEASE && (fl->fl_ltype & LEASE_BREAKING)) {
			/*
			 * Set lease type to actual 'target lease type'
			 * instead of 'READ' returned by procfs.
			 */
			target_type = fcntl(lfd, F_GETLEASE);
			if (target_type < 0) {
				perror("Can't get lease type\n");
				return -1;
			}
			fl->fl_ltype &= ~O_ACCMODE;
			fl->fl_ltype |= target_type;
			break;
		}
	}
	return 0;
}

static int open_break_cb(int ns_root_fd, struct reg_file_info *rfi, void *arg)
{
	int fd, flags = *(int *)arg | O_NONBLOCK;

	fd = openat(ns_root_fd, rfi->path, flags);
	if (fd >= 0) {
		pr_err("Conflicting lease wasn't found\n");
		close(fd);
		return -1;
	} else if (errno != EWOULDBLOCK) {
		pr_perror("Can't break lease");
		return -1;
	}
	return 0;
}

static int break_lease(int lease_type, struct file_desc *desc)
{
	int target_type = lease_type & (~LEASE_BREAKING);
	int break_flags;

	/*
	 * Flags for open call chosen in a way to even
	 * 'target lease type' returned by fcntl(F_GETLEASE)
	 * and lease type from the image.
	 */
	if (target_type == F_UNLCK) {
		break_flags = O_WRONLY;
	} else if (target_type == F_RDLCK) {
		break_flags = O_RDONLY;
	} else {
		pr_err("Incorrect target lease type\n");
		return -1;
	}
	return open_path(desc, open_break_cb, (void *)&break_flags);
}

static int set_file_lease(int fd, int type)
{
	int old_fsuid, ret;
	struct stat st;

	if (fstat(fd, &st)) {
		pr_perror("Can't get file stat (%i)", fd);
		return -1;
	}

	/*
	 * An unprivileged process may take out a lease only if
	 * uid of the file matches the fsuid of the process.
	 */
	old_fsuid = setfsuid(st.st_uid);

	ret = fcntl(fd, F_SETLEASE, type);
	if (ret < 0)
		pr_perror("Can't set lease");

	setfsuid(old_fsuid);
	return ret;
}

static int restore_lease_prebreaking_state(int fd, int fd_type)
{
	int access_flags = fd_type & O_ACCMODE;
	int lease_type = (access_flags == O_RDONLY) ? F_RDLCK : F_WRLCK;

	return set_file_lease(fd, lease_type);
}

static struct fdinfo_list_entry *find_fd_unordered(struct pstree_item *task, int fd)
{
	struct list_head *head = &rsti(task)->fds;
	struct fdinfo_list_entry *fle;

	list_for_each_entry_reverse(fle, head, ps_list) {
		if (fle->fe->fd == fd)
			return fle;
	}
	return NULL;
}

static int restore_breaking_file_lease(FileLockEntry *fle)
{
	struct fdinfo_list_entry *fdle;
	int ret;

	fdle = find_fd_unordered(current, fle->fd);
	if (fdle == NULL) {
		pr_err("Can't get file description\n");
		return -1;
	}

	ret = restore_lease_prebreaking_state(fle->fd, fdle->desc->ops->type);
	if (ret)
		return ret;

	/*
	 * It could be broken by 2 types of open call:
	 * 1. non-blocking: It failed because of the lease.
	 * 2. blocking: It had been blocked at the moment
	 * of dumping, otherwise lease wouldn't be broken.
	 * Thus, it was canceled by CRIU.
	 *
	 * There are no files or leases in image, which will
	 * conflict with each other. Therefore we should explicitly
	 * break leases. Restoring can be done in any order.
	 */
	return break_lease(fle->type, fdle->desc);
}

static int restore_file_lease(FileLockEntry *fle)
{
	sigset_t blockmask, oldmask;
	int signum_fcntl, signum, ret;

	if (fle->type & LEASE_BREAKING) {
		signum_fcntl = fcntl(fle->fd, F_GETSIG);
		signum = signum_fcntl ? signum_fcntl : SIGIO;
		if (signum_fcntl < 0) {
			pr_perror("Can't get file i/o signum");
			return -1;
		}
		if (sigemptyset(&blockmask) || sigaddset(&blockmask, signum) ||
		    sigprocmask(SIG_BLOCK, &blockmask, &oldmask)) {
			pr_perror("Can't block file i/o signal");
			return -1;
		}

		ret = restore_breaking_file_lease(fle);

		if (sigprocmask(SIG_SETMASK, &oldmask, NULL)) {
			pr_perror("Can't restore sigmask");
			ret = -1;
		}
		return ret;
	} else {
		ret = set_file_lease(fle->fd, fle->type);
		if (ret < 0)
			pr_perror("Can't restore non breaking lease");
		return ret;
	}
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

		pr_info("(flock)flag: %d, type: %d, cmd: %d, pid: %d, fd: %d\n", fle->flag, fle->type, cmd, fle->pid,
			fle->fd);

		ret = flock(fle->fd, cmd);
		if (ret < 0) {
			pr_err("Can not set flock!\n");
			goto err;
		}
	} else if (fle->flag & FL_POSIX) {
		struct flock flk;
		memset(&flk, 0, sizeof(flk));

		flk.l_whence = SEEK_SET;
		flk.l_start = fle->start;
		flk.l_len = fle->len;
		flk.l_pid = fle->pid;
		flk.l_type = fle->type;

		pr_info("(posix)flag: %d, type: %d, pid: %d, fd: %d, "
			"start: %8" PRIx64 ", len: %8" PRIx64 "\n",
			fle->flag, fle->type, fle->pid, fle->fd, fle->start, fle->len);

		ret = fcntl(fle->fd, F_SETLKW, &flk);
		if (ret < 0) {
			pr_err("Can not set posix lock!\n");
			goto err;
		}
	} else if (fle->flag & FL_OFD) {
		struct flock flk = {
			.l_whence = SEEK_SET, .l_start = fle->start, .l_len = fle->len, .l_pid = 0, .l_type = fle->type
		};

		pr_info("(ofd)flag: %d, type: %d, pid: %d, fd: %d, "
			"start: %8" PRIx64 ", len: %8" PRIx64 "\n",
			fle->flag, fle->type, fle->pid, fle->fd, fle->start, fle->len);

		ret = fcntl(fle->fd, F_OFD_SETLK, &flk);
		if (ret < 0) {
			pr_err("Can not set ofd lock!\n");
			goto err;
		}
	} else if (fle->flag & FL_LEASE) {
		pr_info("(lease)flag: %d, type: %d, pid: %d, fd: %d, "
			"start: %8" PRIx64 ", len: %8" PRIx64 "\n",
			fle->flag, fle->type, fle->pid, fle->fd, fle->start, fle->len);
		ret = restore_file_lease(fle);
		if (ret < 0)
			goto err;
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

	return restore_file_locks(pid);
}
