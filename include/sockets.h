#ifndef CR_SOCKETS_H__
#define CR_SOCKETS_H__

#include <sys/types.h>
#include <sys/socket.h>
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
extern void release_skopts(SkOptsEntry *);
extern int restore_prepare_socket(int sk);

extern int sk_collect_one(int ino, int family, struct socket_desc *d);
extern int collect_sockets(int pid);
extern int collect_inet_sockets(void);
extern int collect_unix_sockets(void);
extern int fix_external_unix_sockets(void);
extern int resolve_unix_peers(void);

extern void show_unixsk(int fd, struct cr_options *o);
extern void show_inetsk(int fd, struct cr_options *o);
extern void show_sk_queues(int fd, struct cr_options *o);

extern char *skfamily2s(u32 f);
extern char *sktype2s(u32 t);
extern char *skproto2s(u32 p);
extern char *skstate2s(u32 state);

extern struct socket_desc *lookup_socket(int ino, int family);

extern int dump_one_inet(struct fd_parms *p, int lfd, const struct cr_fdset *set);
extern int dump_one_inet6(struct fd_parms *p, int lfd, const struct cr_fdset *set);
extern int dump_one_unix(struct fd_parms *p, int lfd, const struct cr_fdset *set);

extern int inet_collect_one(struct nlmsghdr *h, int family, int type, int proto);
extern int unix_receive_one(struct nlmsghdr *h, void *);

extern int do_dump_opt(int sk, int level, int name, void *val, int len);
#define dump_opt(s, l, n, f)	do_dump_opt(s, l, n, f, sizeof(*f))
extern int do_restore_opt(int sk, int level, int name, void *val, int len);
#define restore_opt(s, l, n, f)	do_restore_opt(s, l, n, f, sizeof(*f))

#define sk_encode_shutdown(img, mask) do {			\
		/* 						\
		 * protobuf SK_SHUTDOWN__ bits match those	\
		 * reported by kernel				\
		 */ 						\
		(img)->shutdown = mask;				\
		if ((img)->shutdown != SK_SHUTDOWN__NONE)	\
			(img)->has_shutdown = true;		\
	} while (0)

static inline int sk_decode_shutdown(int val)
{
	static const int hows[] = {-1, SHUT_RD, SHUT_WR, SHUT_RDWR};
	return hows[val];
}

#endif /* CR_SOCKETS_H__ */
