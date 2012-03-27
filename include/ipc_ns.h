#ifndef CR_IPC_NS_H_
#define CR_IPC_NS_H_

#include "crtools.h"

struct cr_options;
extern void show_ipc_var(int fd, struct cr_options *);
extern void show_ipc_shm(int fd, struct cr_options *);
extern void show_ipc_msg(int fd, struct cr_options *);
extern void show_ipc_sem(int fd, struct cr_options *);
extern int dump_ipc_ns(int ns_pid, struct cr_fdset *fdset);
extern int prepare_ipc_ns(int pid);

#endif /* CR_IPC_NS_H_ */
