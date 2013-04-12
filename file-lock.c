#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "file-lock.h"
#include "parasite.h"
#include "parasite-syscall.h"

struct list_head file_lock_list = LIST_HEAD_INIT(file_lock_list);

struct file_lock *alloc_file_lock(void)
{
	struct file_lock *flock;

	flock = xzalloc(sizeof(*flock));
	if (!flock)
		return NULL;

	INIT_LIST_HEAD(&flock->list);

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

static int dump_one_file_lock(FileLockEntry *fle, const struct cr_fdset *fdset)
{
	pr_info("flag: %d,type: %d,pid: %d,fd: %d,start: %8"PRIx64",len: %8"PRIx64"\n",
		fle->flag, fle->type, fle->pid,	fle->fd, fle->start, fle->len);

	return pb_write_one(fdset_fd(fdset, CR_FD_FILE_LOCKS),
			fle, PB_FILE_LOCK);
}

static int fill_flock_entry(FileLockEntry *fle, const char *fl_flag,
			const char *fl_type, const char *fl_option)
{
	if (!strcmp(fl_flag, "POSIX")) {
		fle->flag |= FL_POSIX;
	} else if (!strcmp(fl_flag, "FLOCK")) {
		fle->flag |= FL_FLOCK;
	} else {
		pr_err("Unknown file lock!\n");
		goto err;
	}

	if (!strcmp(fl_type, "MSNFS")) {
		fle->type |= LOCK_MAND;

		if (!strcmp(fl_option, "READ")) {
			fle->type |= LOCK_READ;
		} else if (!strcmp(fl_option, "RW")) {
			fle->type |= LOCK_RW;
		} else if (!strcmp(fl_option, "WRITE")) {
			fle->type |= LOCK_WRITE;
		} else {
			pr_err("Unknown lock option!\n");
			goto err;
		}
	} else {
		if (!strcmp(fl_option, "UNLCK")) {
			fle->type |= F_UNLCK;
		} else if (!strcmp(fl_option, "WRITE")) {
			fle->type |= F_WRLCK;
		} else if (!strcmp(fl_option, "READ")) {
			fle->type |= F_RDLCK;
		} else {
			pr_err("Unknown lock option!\n");
			goto err;
		}
	}

	return 0;
err:
	return -1;
}

static int get_fd_by_ino(unsigned long i_no, struct parasite_drain_fd *dfds,
			pid_t pid)
{
	int  i;
	char buf[PATH_MAX];
	struct stat fd_stat;

	for (i = 0; i < dfds->nr_fds; i++) {
		snprintf(buf, sizeof(buf), "/proc/%d/fd/%d", pid,
			dfds->fds[i]);

		if (stat(buf, &fd_stat) == -1) {
			pr_msg("Could not get %s stat!\n", buf);
			continue;
		}

		if (fd_stat.st_ino == i_no)
			return dfds->fds[i];
	}

	return -1;
}

int dump_task_file_locks(struct parasite_ctl *ctl,
			struct cr_fdset *fdset,	struct parasite_drain_fd *dfds)
{
	FileLockEntry	 fle;
	struct file_lock *fl;

	pid_t	pid = ctl->pid.real;
	int	ret = 0;

	list_for_each_entry(fl, &file_lock_list, list) {
		if (fl->fl_owner != pid)
			continue;
		pr_info("lockinfo: %lld:%s %s %s %d %02x:%02x:%ld %lld %s\n",
			fl->fl_id, fl->fl_flag, fl->fl_type, fl->fl_option,
			fl->fl_owner, fl->maj, fl->min, fl->i_no,
			fl->start, fl->end);

		file_lock_entry__init(&fle);
		fle.pid = fl->fl_owner;

		ret = fill_flock_entry(&fle, fl->fl_flag, fl->fl_type,
				fl->fl_option);
		if (ret)
			goto err;

		fle.fd = get_fd_by_ino(fl->i_no, dfds, pid);
		if (fle.fd < 0) {
			ret = -1;
			goto err;
		}

		fle.start = fl->start;

		if (!strncmp(fl->end, "EOF", 3))
			fle.len = 0;
		else
			fle.len = (atoll(fl->end) + 1) - fl->start;

		ret = dump_one_file_lock(&fle, fdset);
		if (ret) {
			pr_err("Dump file lock failed!\n");
			goto err;
		}
	}

err:
	return ret;
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
	int fd, ret = -1;
	FileLockEntry *fle;

	fd = open_image(CR_FD_FILE_LOCKS, O_RSTR, pid);
	if (fd < 0) {
		if (errno == ENOENT)
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
			goto err;
	}

	close_safe(&fd);
	return 0;
err:
	close_safe(&fd);
	return ret;
}

int prepare_file_locks(int pid)
{
	if (!opts.handle_file_locks)
		return 0;

	pr_info("Restore file locks.\n");

	return restore_file_locks(pid);
}
