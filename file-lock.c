#include <stdlib.h>
#include <unistd.h>

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
	pr_info("flag: %d,type: %d,pid: %d,fd: %d,start: %8lx,len: %8lx\n",
		fle->flag, fle->type, fle->pid,	fle->fd, fle->start, fle->len);

	return pb_write_one(fdset_fd(fdset, CR_FD_FILE_LOCKS),
			fle, PB_FILE_LOCK);
}
