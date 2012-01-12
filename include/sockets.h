#ifndef CR_SOCKETS_H__
#define CR_SOCKETS_H__

#include <stdbool.h>

struct cr_fdset;
extern int try_dump_socket(char *dir_name, int fd, struct cr_fdset *cr_fdset);

extern int collect_sockets(void);
extern int prepare_sockets(int pid);
extern void show_unixsk(int fd);

#endif /* CR_SOCKETS_H__ */
