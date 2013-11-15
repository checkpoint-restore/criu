#ifndef __CR_RST_INFO_H__
#define __CR_RST_INFO_H__

#include "lock.h"
#include "list.h"

struct task_entries {
	int nr_threads, nr_tasks, nr_helpers;
	futex_t nr_in_progress;
	futex_t start;
	mutex_t	zombie_lock;
};

struct fdt {
	int			nr;		/* How many tasks share this fd table */
	pid_t			pid;		/* Who should restore this fd table */
	/*
	 * The fd table is ready for restoing, if fdt_lock is equal to nr
	 * The fdt table was restrored, if fdt_lock is equal to nr + 1
	 */
	futex_t			fdt_lock;
};

struct rst_info {
	struct list_head	fds;
	struct list_head	eventpoll;
	struct list_head	tty_slaves;

	void			*premmapped_addr;
	unsigned long		premmapped_len;
	unsigned long		clone_flags;

	void			*munmap_restorer;

	int			nr_zombies;

	int service_fd_id;
	struct fdt		*fdt;

	union {
		struct pstree_item	*pgrp_leader;
		futex_t			pgrp_set;
	};
};

#endif /* __CR_RST_INFO_H__ */
