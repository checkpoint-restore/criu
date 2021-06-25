#ifndef __CR_PIDFD_STORE_H__
#define __CR_PIDFD_STORE_H__

#include <sys/types.h>

struct pidfd_entry {
	pid_t				pid;
	int				pidfd;
	struct hlist_node		hash; /* To lookup pidfd by pid */
};

extern int pidfd_store_sk;

int init_pidfd_store_sk(pid_t pid, int fd);
int init_pidfd_store_hash(void);
void free_pidfd_store(void);
int send_pidfd_entry(pid_t pid);
struct pidfd_entry *find_pidfd_entry_by_pid(pid_t pid);
int check_pidfd_entry_state(struct pidfd_entry *entry);

#endif /* __CR_PIDFD_STORE_H__ */