#ifndef CR_SOCKETS_H__
#define CR_SOCKETS_H__

#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

#include "types.h"

#include "protobuf.h"
#include "../protobuf/sk-opts.pb-c.h"

struct fdinfo_list_entry;
struct sk_opts_entry;
struct cr_options;
struct file_desc;
struct fd_parms;
struct cr_fdset;
struct nlmsghdr;

struct socket_desc {
	unsigned int		family;
	unsigned int		ino;
	struct socket_desc	*next;
	int			already_dumped;
};

extern int dump_socket(struct fd_parms *p, int lfd, const struct cr_fdset *cr_fdset);
extern int dump_socket_opts(int sk, SkOptsEntry *soe);
extern int restore_socket_opts(int sk, SkOptsEntry *soe);
extern void show_socket_opts(SkOptsEntry *soe);

extern int sk_collect_one(int ino, int family, struct socket_desc *d);
extern int collect_sockets(void);
extern int collect_inet_sockets(void);
extern int collect_unix_sockets(void);
extern int fix_external_unix_sockets(void);
extern int resolve_unix_peers(void);
extern int run_unix_connections(void);

extern void show_unixsk(int fd, struct cr_options *o);
extern void show_inetsk(int fd, struct cr_options *o);
extern void show_sk_queues(int fd, struct cr_options *o);

extern char *skfamily2s(u32 f);
extern char *sktype2s(u32 t);
extern char *skproto2s(u32 p);
extern char *skstate2s(u32 state);

extern struct socket_desc *lookup_socket(int ino);

extern int dump_one_inet(struct fd_parms *p, int lfd, const struct cr_fdset *set);
extern int dump_one_unix(struct fd_parms *p, int lfd, const struct cr_fdset *set);

extern int inet_collect_one(struct nlmsghdr *h, int family, int type, int proto);
extern int unix_receive_one(struct nlmsghdr *h);

extern int do_dump_opt(int sk, int name, void *val, int len);

#endif /* CR_SOCKETS_H__ */
