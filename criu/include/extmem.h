#ifndef __CR_EXTMEM_H__
#define __CR_EXTMEM_H__

#include <stdbool.h>
#include <sys/types.h>

int extmem_init(void);
bool extmem_is_active(void);
int extmem_acquire_provider_fd(void);
void extmem_release_provider_fd(void);
int extmem_open_image(const char *name, int flags, int *fd);
int extmem_get_vma(pid_t pid, unsigned int vma_id, unsigned long vaddr, unsigned long length, int *fd);
int extmem_get_shared(unsigned long shmid, unsigned long length, int *fd);
int extmem_wait_ready(void);
int extmem_commit(void);
int extmem_abort(void);

#endif
