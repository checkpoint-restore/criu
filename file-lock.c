#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <fcntl.h>
#include <string.h>

#include "file-lock.h"

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

int dump_one_file_lock(FileLockEntry *fle, const struct cr_fdset *fdset)
{
	pr_info("flag: %d,type: %d,pid: %d,fd: %d,start: %8"PRIx64",len: %8"PRIx64"\n",
		fle->flag, fle->type, fle->pid,	fle->fd, fle->start, fle->len);

	return pb_write_one(fdset_fd(fdset, CR_FD_FILE_LOCKS),
			fle, PB_FILE_LOCK);
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
			pr_err("Unknow flock type!\n");
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
		pr_err("Unknow file lock style!\n");
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

	fd = open_image_ro(CR_FD_FILE_LOCKS, pid);
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
