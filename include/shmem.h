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
	futex_t		lock;
};

struct _VmaEntry;
extern int collect_shmem(int pid, struct _VmaEntry *vi);
extern int prepare_shmem_restore(void);
extern void show_saved_shmems(void);
extern int get_shmem_fd(int pid, VmaEntry *vi);

extern unsigned long nr_shmems;
extern unsigned int rst_shmems;

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
