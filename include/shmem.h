#ifndef __CR_SHMEM_H__
#define __CR_SHMEM_H__

#include "lock.h"

#include "protobuf/vma.pb-c.h"

/*
 * pid is a pid of a creater
 * start, end are used for open mapping
 * fd is a file discriptor, which is valid for creater,
 * it's opened in cr-restor, because pgoff may be non zero
 */
struct shmem_info {
	unsigned long	shmid;
	unsigned long	start;
	unsigned long	end;
	unsigned long	size;
	int		pid;
	int		fd;

	/*
	 * 0. lock is initilized to zero
	 * 1. the master opens a descriptor and set lock to 1
	 * 2. slaves open their descriptors and increment lock
	 * 3. the master waits all slaves on lock. After that
	 *    it can close the descriptor.
	 */
	futex_t		lock;

	/*
	 * Here is a problem, that we don't know, which process will restore
	 * an region. Each time when we	found a process with a smaller pid,
	 * we reset self_count, so we can't have only one counter.
	 */
	int		count;		/* the number of regions */
	int		self_count;	/* the number of regions, which belongs to "pid" */
};

struct _VmaEntry;
extern int collect_shmem(int pid, struct _VmaEntry *vi);
extern int prepare_shmem_restore(void);
extern void show_saved_shmems(void);
extern int get_shmem_fd(int pid, VmaEntry *vi);

extern unsigned long nr_shmems;
extern unsigned long rst_shmems;

extern int cr_dump_shmem(void);
extern int add_shmem_area(pid_t pid, VmaEntry *vma);

static always_inline struct shmem_info *
find_shmem(struct shmem_info *shmems, int nr, unsigned long shmid)
{
	struct shmem_info *si;
	int i;

	for (i = 0, si = shmems; i < nr; i++, si++)
		if (si->shmid == shmid)
			return si;

	return NULL;
}

#endif /* __CR_SHMEM_H__ */
