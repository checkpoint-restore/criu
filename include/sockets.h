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
extern int fix_external_unix_sockets(void);
extern int collect_inet_sockets(void);
extern int collect_unix_sockets(void);
extern int resolve_unix_peers(void);
extern int run_unix_connections(void);
struct cr_options;
extern void show_unixsk(int fd, struct cr_options *);
extern void show_inetsk(int fd, struct cr_options *);
extern void show_sk_queues(int fd, struct cr_options *);

char *skfamily2s(u32 f);
char *sktype2s(u32 t);
char *skproto2s(u32 p);
char *skstate2s(u32 state);

struct socket_desc {
	unsigned int		family;
	unsigned int		ino;
	struct socket_desc	*next;
	int			already_dumped;
};

struct socket_desc *lookup_socket(int ino);
int sk_collect_one(int ino, int family, struct socket_desc *d);
int dump_one_inet(struct socket_desc *_sk, struct fd_parms *p,
		int lfd, const struct cr_fdset *cr_fdset);
int dump_one_unix(const struct socket_desc *_sk, struct fd_parms *p,
		int lfd, const struct cr_fdset *cr_fdset);
struct nlmsghdr;
int inet_collect_one(struct nlmsghdr *h, int family, int type, int proto);
int unix_receive_one(struct nlmsghdr *h);
#endif /* CR_SOCKETS_H__ */
