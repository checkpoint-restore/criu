#ifndef IPC_NS_H_
#define IPC_NS_H_

#include "crtools.h"

extern void show_ipc_ns(int fd);
extern int dump_ipc_ns(int ns_pid, struct cr_fdset *fdset);
extern int prepare_ipc_ns(int pid);

#endif /* IPC_NS_H_ */
