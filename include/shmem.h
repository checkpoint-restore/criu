#ifndef __CR_SHMEM_H__
#define __CR_SHMEM_H__

#include "../protobuf/vma.pb-c.h"

int prepare_shmem_pid(int pid);
int prepare_shmem_restore(void);
void show_saved_shmems(void);
int get_shmem_fd(int pid, VmaEntry *vi);

struct shmems;
extern struct shmems *rst_shmems;

int cr_dump_shmem(void);
int add_shmem_area(pid_t pid, VmaEntry *vma);
int init_shmem_dump(void);
void fini_shmem_dump(void);
#endif
