#ifndef __CR_PIDFD_STORE_H__
#define __CR_PIDFD_STORE_H__

#include <sys/types.h>

int init_pidfd_store_sk(pid_t pid, int fd);
int init_pidfd_store_hash(void);
void free_pidfd_store(void);
int pidfd_store_add(pid_t pid);
int pidfd_store_check_pid_reuse(pid_t pid);
bool pidfd_store_ready(void);

#endif /* __CR_PIDFD_STORE_H__ */
