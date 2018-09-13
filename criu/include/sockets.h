#ifndef __CR_SOCKETS_H__
#define __CR_SOCKETS_H__

#include <alloca.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "images/sk-opts.pb-c.h"
#include "images/fdinfo.pb-c.h"

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
	struct ns_id		*sk_ns;
	int			already_dumped;
};

extern int dump_socket(struct fd_parms *p, int lfd, FdinfoEntry *);
extern int dump_socket_opts(int sk, SkOptsEntry *soe);
extern int restore_socket_opts(int sk, SkOptsEntry *soe);
extern void release_skopts(SkOptsEntry *);
extern int restore_prepare_socket(int sk);
extern void preload_socket_modules(void);

extern bool socket_test_collect_bit(unsigned int family, unsigned int proto);

extern int sk_collect_one(unsigned ino, int family, struct socket_desc *d, struct ns_id *ns);
struct ns_id;
extern int collect_sockets(struct ns_id *);
extern struct collect_image_info inet_sk_cinfo;
extern struct collect_image_info unix_sk_cinfo;
extern int add_fake_unix_queuers(void);
extern int fix_external_unix_sockets(void);
extern int prepare_scms(void);
extern int unix_note_scm_rights(int id_for, uint32_t *file_ids, int *fds, int n_ids);

extern struct collect_image_info netlink_sk_cinfo;

extern struct socket_desc *lookup_socket_ino(unsigned int ino, int family);
extern struct socket_desc *lookup_socket(unsigned int ino, int family, int proto);

extern const struct fdtype_ops unix_dump_ops;
extern const struct fdtype_ops inet_dump_ops;
extern const struct fdtype_ops inet6_dump_ops;
extern const struct fdtype_ops netlink_dump_ops;
extern const struct fdtype_ops packet_dump_ops;

extern int inet_collect_one(struct nlmsghdr *h, int family, int type, struct ns_id *ns);
extern int unix_receive_one(struct nlmsghdr *h, struct ns_id *ns, void *);
extern int netlink_receive_one(struct nlmsghdr *hdr, struct ns_id *ns, void *arg);

extern int unix_sk_id_add(unsigned int ino);
extern int unix_sk_ids_parse(char *optarg);
extern int unix_prepare_root_shared(void);

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

extern int set_netns(uint32_t ns_id);

#ifndef SIOCGSKNS
#define SIOCGSKNS      0x894C          /* get socket network namespace */
#endif

extern int kerndat_socket_netns(void);
extern int kerndat_socket_unix_file(void);

extern const char *tcp_state_name(unsigned int state, char *nm, size_t size);
extern const char *socket_type_name(unsigned int type, char *nm, size_t size);
extern const char *socket_family_name(unsigned int family, char *nm, size_t size);
extern const char *socket_proto_name(unsigned int proto, char *nm, size_t size);

#define __tcp_state_name(state, a)	tcp_state_name(state, a, sizeof(a))
#define __socket_type_name(type, a)	socket_type_name(type, a, sizeof(a))
#define __socket_family_name(family, a)	socket_family_name(family, a, sizeof(a))
#define __socket_proto_name(proto, a)	socket_proto_name(proto, a, sizeof(a))

#define __socket_info_helper(__h, __v)				\
	({							\
		char *__nm = alloca(32);			\
		const char *__r = __h(__v, __nm, 32);		\
		__r;						\
	})

#define ___tcp_state_name(state)	__socket_info_helper(tcp_state_name, state)
#define ___socket_type_name(type)	__socket_info_helper(socket_type_name, type)
#define ___socket_family_name(family)	__socket_info_helper(socket_family_name, family)
#define ___socket_proto_name(proto)	__socket_info_helper(socket_proto_name, proto)

#endif /* __CR_SOCKETS_H__ */
