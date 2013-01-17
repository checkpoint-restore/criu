#ifndef __FILE_LOCK_H__
#define __FILE_LOCK_H__

#include "crtools.h"
#include "protobuf.h"
#include "../protobuf/file-lock.pb-c.h"

struct file_lock {
	long long	fl_id;
	char		fl_flag[10];
	char		fl_type[15];
	char		fl_option[10];

	pid_t		fl_owner;
	int		maj, min;
	unsigned long	i_no;
	long long	start;
	char		end[32];

	struct list_head list;		/* list of all file locks */
};

extern struct list_head file_lock_list;

extern struct file_lock *alloc_file_lock(void);
extern void free_file_locks(void);

#endif /* __FILE_LOCK_H__ */
