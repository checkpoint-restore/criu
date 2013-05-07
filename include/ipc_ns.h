#ifndef __CR_IPC_NS_H__
#define __CR_IPC_NS_H__

#include "crtools.h"

struct cr_options;
extern void show_ipc_var(int fd);
extern void show_ipc_shm(int fd);
extern void show_ipc_msg(int fd);
extern void show_ipc_sem(int fd);
extern int dump_ipc_ns(int ns_pid, const struct cr_fdset *fdset);
extern int prepare_ipc_ns(int pid);

extern struct ns_desc ipc_ns_desc;

#endif /* __CR_IPC_NS_H__ */
