#ifndef __CRTOOLS_SOCKETS_H__
#define __CRTOOLS_SOCKETS_H__
int collect_sockets(void);
struct cr_fdset;
int __try_dump_socket(char *dir_name, char *fd_name, struct cr_fdset *cr_fdset);
int prepare_sockets(int pid);
void show_unixsk(char *name, int fd, bool show_header);
#endif
