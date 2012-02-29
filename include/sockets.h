#ifndef CR_SOCKETS_H__
#define CR_SOCKETS_H__

#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

struct sk_queue_item {
	int		fd;
	int		type;
	unsigned int	sk_id;
};

struct cr_fdset;
extern int try_dump_socket(pid_t pid, int fd, const struct cr_fdset *cr_fdset);

extern int collect_sockets(void);
extern int prepare_sockets(int pid);
extern void show_unixsk(int fd);
extern void show_inetsk(int fd);

#endif /* CR_SOCKETS_H__ */
