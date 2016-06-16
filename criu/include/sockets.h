#ifndef __CR_SOCKETS_H__
#define __CR_SOCKETS_H__

#include <stdbool.h>
#include <sys/socket.h>

#include "asm/types.h"

#include "protobuf.h"
#include "images/sk-opts.pb-c.h"

struct fdinfo_list_entry;
struct sk_opts_entry;
struct file_desc;
struct fd_parms;
struct cr_imgset;
struct nlmsghdr;
struct cr_img;

struct socket_desc {
	unsigned int		family;
	unsigned int		ino;
	struct socket_desc	*next;
	int			already_dumped;
};

extern int dump_socket(struct fd_parms *p, int lfd, struct cr_img *);
extern int dump_socket_opts(int sk, SkOptsEntry *soe);
extern int restore_socket_opts(int sk, SkOptsEntry *soe);
extern void release_skopts(SkOptsEntry *);
extern int restore_prepare_socket(int sk);
extern void preload_socket_modules();

extern bool socket_test_collect_bit(unsigned int family, unsigned int proto);

extern int sk_collect_one(unsigned ino, int family, struct socket_desc *d);
struct ns_id;
extern int collect_sockets(struct ns_id *);
extern int collect_inet_sockets(void);
extern struct collect_image_info unix_sk_cinfo;
extern int fix_external_unix_sockets(void);

extern struct collect_image_info netlink_sk_cinfo;

extern struct socket_desc *lookup_socket(unsigned ino, int family, int proto);

extern const struct fdtype_ops unix_dump_ops;
extern const struct fdtype_ops inet_dump_ops;
extern const struct fdtype_ops inet6_dump_ops;
extern const struct fdtype_ops netlink_dump_ops;
extern const struct fdtype_ops packet_dump_ops;

extern int inet_collect_one(struct nlmsghdr *h, int family, int type);
extern int unix_receive_one(struct nlmsghdr *h, void *);
extern int netlink_receive_one(struct nlmsghdr *hdr, void *arg);

extern int unix_sk_id_add(ino_t ino);
extern int unix_sk_ids_parse(char *optarg);

extern int do_dump_opt(int sk, int level, int name, void *val, int len);
#define dump_opt(s, l, n, f)	do_dump_opt(s, l, n, f, sizeof(*f))
extern int do_restore_opt(int sk, int level, int name, void *val, int len);
#define restore_opt(s, l, n, f)	do_restore_opt(s, l, n, f, sizeof(*f))

#define sk_encode_shutdown(img, mask) do {			\
		/*						\
		 * protobuf SK_SHUTDOWN__ bits match those	\
		 * reported by kernel				\
		 */						\
		(img)->shutdown = mask;				\
		if ((img)->shutdown != SK_SHUTDOWN__NONE)	\
			(img)->has_shutdown = true;		\
	} while (0)

static inline int sk_decode_shutdown(int val)
{
	static const int hows[] = {-1, SHUT_RD, SHUT_WR, SHUT_RDWR};
	return hows[val];
}

#define USK_EXT_PARAM "ext-unix-sk"

#ifndef NETLINK_SOCK_DIAG
#define NETLINK_SOCK_DIAG NETLINK_INET_DIAG
#endif

#endif /* __CR_SOCKETS_H__ */
