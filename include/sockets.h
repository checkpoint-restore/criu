#ifndef CR_SOCKETS_H__
#define CR_SOCKETS_H__

#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

struct cr_fdset;
struct fd_parms;
extern int dump_socket(struct fd_parms *p, int lfd,
		const struct cr_fdset *cr_fdset);

struct fdinfo_list_entry;
struct list_head *find_inetsk_fd(int id);
extern int collect_sockets(void);
extern int collect_inet_sockets(void);
extern int collect_unix_sockets(int pid);
extern int prepare_sockets(int pid);
extern int open_inet_sk(struct list_head *);
struct cr_options;
extern void show_unixsk(int fd, struct cr_options *);
extern void show_inetsk(int fd, struct cr_options *);
extern void show_sk_queues(int fd, struct cr_options *);

#endif /* CR_SOCKETS_H__ */
