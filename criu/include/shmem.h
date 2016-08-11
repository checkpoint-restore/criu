#ifndef __CR_SHMEM_H__
#define __CR_SHMEM_H__

#include "asm/int.h"
#include "lock.h"
#include "images/vma.pb-c.h"

struct _VmaEntry;
struct vma_area;

extern int collect_shmem(int pid, struct vma_area *vma);
extern int collect_sysv_shmem(unsigned long shmid, unsigned long size);
extern int cr_dump_shmem(void);
extern int add_shmem_area(pid_t pid, VmaEntry *vma, u64 *map);
extern int fixup_sysv_shmems(void);

#define SYSV_SHMEM_SKIP_FD	(0x7fffffff)

#endif /* __CR_SHMEM_H__ */
