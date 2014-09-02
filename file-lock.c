#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "cr_options.h"
#include "fdset.h"
#include "files.h"
#include "image.h"
#include "servicefd.h"
#include "file-lock.h"
#include "parasite.h"
#include "parasite-syscall.h"

struct file_lock_rst {
	FileLockEntry *fle;
	struct list_head l;
};

struct list_head file_lock_list = LIST_HEAD_INIT(file_lock_list);

static int collect_one_file_lock(void *o, ProtobufCMessage *m)
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
	.flags = COLLECT_OPTIONAL,
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

	return pb_write_one(fdset_fd(glob_fdset, CR_FD_FILE_LOCKS),
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
			pr_err("Unresolved lock found pid %d ino %ld\n",
					fl->fl_owner, fl->i_no);
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

static inline bool lock_file_match(struct file_lock *fl, struct fd_parms *p)
{
	return fl->i_no == p->stat.st_ino &&
		makedev(fl->maj, fl->min) == p->stat.st_dev;
}

static int lock_check_fd(int lfd, struct file_lock *fl)
{
	int ret;

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
		if (fl->fl_ltype == F_RDLCK)
			flock(lfd, LOCK_SH);
	}

	return 1;
}

int note_file_lock(struct pid *pid, int fd, int lfd, struct fd_parms *p)
{
	struct file_lock *fl;

	list_for_each_entry(fl, &file_lock_list, list) {
		if (!lock_file_match(fl, p))
			continue;

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

static int restore_file_locks_legacy(int pid)
{
	int fd, ret = -1;
	FileLockEntry *fle;

	fd = open_image(CR_FD_FILE_LOCKS_PID, O_RSTR | O_OPT, pid);
	if (fd < 0) {
		if (fd == -ENOENT)
			return 0;
		else
			return -1;
	}

	while (1) {
		ret = pb_read_one_eof(fd, &fle, PB_FILE_LOCK);
		if (ret <= 0)
			break;

		ret = restore_file_lock(fle);
		file_lock_entry__free_unpacked(fle, NULL);
		if (ret)
			break;
	}

	close_safe(&fd);
	return ret;
}

int prepare_file_locks(int pid)
{
	if (!opts.handle_file_locks)
		return 0;

	pr_info("Restore file locks.\n");
	if (file_locks_cinfo.flags & COLLECT_HAPPENED)
		return restore_file_locks(pid);

	return restore_file_locks_legacy(pid);
}
