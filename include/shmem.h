#ifndef __CR_SHMEM_H__
#define __CR_SHMEM_H__
int prepare_shmem_pid(int pid);
int prepare_shmem_restore(void);
void show_saved_shmems(void);
struct vma_entry;
int get_shmem_fd(int pid, struct vma_entry *vi);

struct shmems;
extern struct shmems *rst_shmems;
#endif
