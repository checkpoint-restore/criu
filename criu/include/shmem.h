#ifndef __CR_SHMEM_H__
#define __CR_SHMEM_H__

#include "lock.h"
#include "images/vma.pb-c.h"

struct _VmaEntry;
extern int collect_shmem(int pid, struct _VmaEntry *vi);
extern int collect_sysv_shmem(unsigned long shmid, unsigned long size);
extern void show_saved_shmems(void);
extern int get_shmem_fd(int pid, VmaEntry *vi);
extern int get_sysv_shmem_fd(struct _VmaEntry *vi);
extern int cr_dump_shmem(void);
extern int add_shmem_area(pid_t pid, VmaEntry *vma);
extern int fixup_sysv_shmems(void);

#define SYSV_SHMEM_SKIP_FD	(0x7fffffff)

#endif /* __CR_SHMEM_H__ */
