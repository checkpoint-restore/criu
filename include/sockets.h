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
struct file_desc;
struct fdinfo_entry;
extern int collect_sockets(void);
extern int dump_external_sockets(void);
extern int collect_inet_sockets(void);
extern int collect_unix_sockets(void);
extern int resolve_unix_peers(void);
extern int run_unix_connections(void);
struct cr_options;
extern void show_unixsk(int fd, struct cr_options *);
extern void show_inetsk(int fd, struct cr_options *);
extern void show_sk_queues(int fd, struct cr_options *);

#endif /* CR_SOCKETS_H__ */
