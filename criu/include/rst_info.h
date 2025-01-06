#ifndef __CR_RST_INFO_H__
#define __CR_RST_INFO_H__

#include "common/lock.h"
#include "common/list.h"
#include "vma.h"
#include "kerndat.h"
#include "images/mm.pb-c.h"
#include "images/core.pb-c.h"

struct task_entries {
	int nr_threads, nr_tasks, nr_helpers;
	futex_t nr_in_progress;
	futex_t start;
	atomic_t cr_err;
	mutex_t userns_sync_lock;
	mutex_t last_pid_mutex;
};

struct fdt {
	int nr;	   /* How many tasks share this fd table */
	pid_t pid; /* Who should restore this fd table */
	/*
	 * The fd table is ready for restoing, if fdt_lock is equal to nr
	 * The fdt table was restrored, if fdt_lock is equal to nr + 1
	 */
	futex_t fdt_lock;
};

struct rst_rseq {
	uint64_t rseq_abi_pointer;
	uint64_t rseq_cs_pointer;
};

struct rst_info {
	struct list_head fds;

	void *premmapped_addr;
	unsigned long premmapped_len;
	unsigned long clone_flags;

	void *munmap_restorer;

	int service_fd_id;
	struct fdt *fdt;

	struct vm_area_list vmas;
	MmEntry *mm;
	struct list_head vma_io;
	unsigned int pages_img_id;

	u32 cg_set;

	union {
		struct pstree_item *pgrp_leader;
		futex_t pgrp_set;
	};

	struct file_desc *cwd;
	struct file_desc *root;
	bool has_umask;
	u32 umask;

	/*
	 * We set this flag when process has seccomp filters
	 * so that we know to suspend them before we unmap the
	 * restorer blob.
	 */
	bool has_seccomp;
	/*
	 * To be compatible with old images where filters
	 * are bound to group leader and we need to use tsync flag.
	 */
	bool has_old_seccomp_filter;

	struct rst_rseq *rseqe;

	futex_t shstk_enable;
	futex_t shstk_unlock;

	void *breakpoint;
};

extern struct task_entries *task_entries;

static inline void lock_last_pid(void)
{
	mutex_lock(&task_entries->last_pid_mutex);
}

static inline void unlock_last_pid(void)
{
	mutex_unlock(&task_entries->last_pid_mutex);
}

#endif /* __CR_RST_INFO_H__ */
