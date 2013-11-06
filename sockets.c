#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/filter.h>
#include <string.h>

#include "libnetlink.h"
#include "sockets.h"
#include "unix_diag.h"
#include "inet_diag.h"
#include "packet_diag.h"
#include "netlink_diag.h"
#include "files.h"
#include "util-pie.h"
#include "sk-packet.h"
#include "namespaces.h"
#include "net.h"

#ifndef NETLINK_SOCK_DIAG
#define NETLINK_SOCK_DIAG NETLINK_INET_DIAG
#endif

#ifndef SOCK_DIAG_BY_FAMILY
#define SOCK_DIAG_BY_FAMILY 20
#endif

#ifndef SOCKFS_MAGIC
#define SOCKFS_MAGIC	0x534F434B
#endif

#define SK_HASH_SIZE		32

#ifndef SO_GET_FILTER
#define SO_GET_FILTER	SO_ATTACH_FILTER
#endif

enum socket_cl_bits
{
	NETLINK_CL_BIT,
	INET_TCP_CL_BIT,
	INET_UDP_CL_BIT,
	INET_UDPLITE_CL_BIT,
	INET6_TCP_CL_BIT,
	INET6_UDP_CL_BIT,
	INET6_UDPLITE_CL_BIT,
	UNIX_CL_BIT,
	PACKET_CL_BIT,
	_MAX_CL_BIT,
};

#define MAX_CL_BIT (_MAX_CL_BIT - 1)

static DECLARE_BITMAP(socket_cl_bits, MAX_CL_BIT);

static inline
enum socket_cl_bits get_collect_bit_nr(unsigned int family, unsigned int proto)
{
	if (family == AF_NETLINK)
		return NETLINK_CL_BIT;
	if (family == AF_UNIX)
		return UNIX_CL_BIT;
	if (family == AF_PACKET)
		return PACKET_CL_BIT;
	if (family == AF_INET) {
		if (proto == IPPROTO_TCP)
			return INET_TCP_CL_BIT;
		if (proto == IPPROTO_UDP)
			return INET_UDP_CL_BIT;
		if (proto == IPPROTO_UDPLITE)
			return INET_UDPLITE_CL_BIT;
	}
	if (family == AF_INET6) {
		if (proto == IPPROTO_TCP)
			return INET6_TCP_CL_BIT;
		if (proto == IPPROTO_UDP)
			return INET6_UDP_CL_BIT;
		if (proto == IPPROTO_UDPLITE)
			return INET6_UDPLITE_CL_BIT;
	}

	pr_err("Unknown pair family %d proto %d\n", family, proto);
	BUG();
	return -1;
}

static void set_collect_bit(unsigned int family, unsigned int proto)
{
	enum socket_cl_bits nr;

	nr = get_collect_bit_nr(family, proto);
	set_bit(nr, socket_cl_bits);
}

bool socket_test_collect_bit(unsigned int family, unsigned int proto)
{
	enum socket_cl_bits nr;

	nr = get_collect_bit_nr(family, proto);
	return test_bit(nr, socket_cl_bits) != 0;
}

static int dump_bound_dev(int sk, SkOptsEntry *soe)
{
	int ret;
	char dev[IFNAMSIZ];
	socklen_t len = sizeof(dev);

	ret = getsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE, &dev, &len);
	if (ret) {
		pr_perror("Can't get bound dev");
		return ret;
	}

	if (len == 0)
		return 0;

	pr_debug("\tDumping %s bound dev for sk\n", dev);
	soe->so_bound_dev = xmalloc(len);
	if (soe->so_bound_dev == NULL)
		return -1;
	strcpy(soe->so_bound_dev, dev);
	return 0;
}

static int restore_bound_dev(int sk, SkOptsEntry *soe)
{
	char *n = soe->so_bound_dev;

	if (!n)
		return 0;

	pr_debug("\tBinding socket to %s dev\n", n);
	return do_restore_opt(sk, SOL_SOCKET, SO_BINDTODEVICE, n, strlen(n));
}

/*
 * Protobuf handles le/be himself, but the sock_filter is not just u64,
 * it's a structure and we have to preserve the fields order to be able
 * to move socket image across architectures.
 */

static void encode_filter(struct sock_filter *f, uint64_t *img, int n)
{
	int i;

	BUILD_BUG_ON(sizeof(*f) != sizeof(*img));

	for (i = 0; i < n; i++)
		img[i] = ((uint64_t)f[i].code << 48) |
			 ((uint64_t)f[i].jt << 40) |
			 ((uint64_t)f[i].jf << 32) |
			 ((uint64_t)f[i].k << 0);
}

static void decode_filter(uint64_t *img, struct sock_filter *f, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		f[i].code = img[i] >> 48;
		f[i].jt = img[i] >> 40;
		f[i].jf = img[i] >> 32;
		f[i].k = img[i] >> 0;
	}
}

static int dump_socket_filter(int sk, SkOptsEntry *soe)
{
	socklen_t len = 0;
	int ret;
	struct sock_filter *flt;

	ret = getsockopt(sk, SOL_SOCKET, SO_GET_FILTER, NULL, &len);
	if (ret) {
		pr_perror("Can't get socket filter len");
		return ret;
	}

	if (!len) {
		pr_info("No filter for socket\n");
		return 0;
	}

	flt = xmalloc(len * sizeof(*flt));
	if (!flt)
		return -1;

	ret = getsockopt(sk, SOL_SOCKET, SO_GET_FILTER, flt, &len);
	if (ret) {
		pr_perror("Can't get socket filter");
		xfree(flt);
		return ret;
	}

	soe->so_filter = xmalloc(len * sizeof(*soe->so_filter));
	if (!soe->so_filter) {
		xfree(flt);
		return -1;
	}

	encode_filter(flt, soe->so_filter, len);
	soe->n_so_filter = len;
	xfree(flt);
	return 0;
}

static int restore_socket_filter(int sk, SkOptsEntry *soe)
{
	int ret;
	struct sock_fprog sfp;

	if (!soe->n_so_filter)
		return 0;

	pr_info("Restoring socket filter\n");
	sfp.len = soe->n_so_filter;
	sfp.filter = xmalloc(soe->n_so_filter * sfp.len);
	if (!sfp.filter)
		return -1;

	decode_filter(soe->so_filter, sfp.filter, sfp.len);
	ret = restore_opt(sk, SOL_SOCKET, SO_ATTACH_FILTER, &sfp);
	xfree(sfp.filter);

	return ret;
}

static struct socket_desc *sockets[SK_HASH_SIZE];

struct socket_desc *lookup_socket(int ino, int family, int proto)
{
	struct socket_desc *sd;

	if (!socket_test_collect_bit(family, proto)) {
		pr_err("Sockets (family %d, proto %d) are not collected\n",
								family, proto);
		return ERR_PTR(-EINVAL);
	}

	pr_debug("\tSearching for socket %x (family %d)\n", ino, family);
	for (sd = sockets[ino % SK_HASH_SIZE]; sd; sd = sd->next)
		if (sd->ino == ino) {
			BUG_ON(sd->family != family);
			return sd;
		}

	return NULL;
}

int sk_collect_one(int ino, int family, struct socket_desc *d)
{
	struct socket_desc **chain;

	d->ino		= ino;
	d->family	= family;
	d->already_dumped = 0;

	chain = &sockets[ino % SK_HASH_SIZE];
	d->next = *chain;
	*chain = d;

	return 0;
}

int do_restore_opt(int sk, int level, int name, void *val, int len)
{
	if (setsockopt(sk, level, name, val, len) < 0) {
		pr_perror("Can't set %d:%d (len %d)", level, name, len);
		return -1;
	}

	return 0;
}

/*
 * Set sizes of buffers to maximum and prevent blocking
 * Caller of this fn should call other socket restoring
 * routines to drop the non-blocking and set proper send
 * and receive buffers.
 */
int restore_prepare_socket(int sk)
{
	int flags;

	/* In kernel a bufsize has type int and a value is doubled. */
	u32 maxbuf = INT_MAX / 2;

	if (restore_opt(sk, SOL_SOCKET, SO_SNDBUFFORCE, &maxbuf))
		return -1;
	if (restore_opt(sk, SOL_SOCKET, SO_RCVBUFFORCE, &maxbuf))
		return -1;

	/* Prevent blocking on restore */
	flags = fcntl(sk, F_GETFL, 0);
	if (flags == -1) {
		pr_perror("Unable to get flags for %d", sk);
		return -1;
	}
	if (fcntl(sk, F_SETFL, flags | O_NONBLOCK) ) {
		pr_perror("Unable to set O_NONBLOCK for %d", sk);
		return -1;
	}

	return 0;
}

int restore_socket_opts(int sk, SkOptsEntry *soe)
{
	int ret = 0, val;
	struct timeval tv;

	pr_info("%d restore sndbuf %d rcv buf %d\n", sk, soe->so_sndbuf, soe->so_rcvbuf);

	/* setsockopt() multiplies the input values by 2 */
	val = soe->so_sndbuf / 2;
	ret |= restore_opt(sk, SOL_SOCKET, SO_SNDBUFFORCE, &val);
	val = soe->so_rcvbuf / 2;
	ret |= restore_opt(sk, SOL_SOCKET, SO_RCVBUFFORCE, &val);

	if (soe->has_so_priority) {
		pr_debug("\trestore priority %d for socket\n", soe->so_priority);
		ret |= restore_opt(sk, SOL_SOCKET, SO_PRIORITY, &soe->so_priority);
	}
	if (soe->has_so_rcvlowat) {
		pr_debug("\trestore rcvlowat %d for socket\n", soe->so_rcvlowat);
		ret |= restore_opt(sk, SOL_SOCKET, SO_RCVLOWAT, &soe->so_rcvlowat);
	}
	if (soe->has_so_mark) {
		pr_debug("\trestore mark %d for socket\n", soe->so_mark);
		ret |= restore_opt(sk, SOL_SOCKET, SO_MARK, &soe->so_mark);
	}
	if (soe->has_so_passcred && soe->so_passcred) {
		val = 1;
		pr_debug("\tset passcred for socket\n");
		ret |= restore_opt(sk, SOL_SOCKET, SO_PASSCRED, &val);
	}
	if (soe->has_so_passsec && soe->so_passsec) {
		val = 1;
		pr_debug("\tset passsec for socket\n");
		ret |= restore_opt(sk, SOL_SOCKET, SO_PASSSEC, &val);
	}
	if (soe->has_so_dontroute && soe->so_dontroute) {
		val = 1;
		pr_debug("\tset dontroute for socket\n");
		ret |= restore_opt(sk, SOL_SOCKET, SO_DONTROUTE, &val);
	}
	if (soe->has_so_no_check && soe->so_no_check) {
		val = 1;
		pr_debug("\tset no_check for socket\n");
		ret |= restore_opt(sk, SOL_SOCKET, SO_NO_CHECK, &val);
	}

	tv.tv_sec = soe->so_snd_tmo_sec;
	tv.tv_usec = soe->so_snd_tmo_usec;
	ret |= restore_opt(sk, SOL_SOCKET, SO_SNDTIMEO, &tv);

	tv.tv_sec = soe->so_rcv_tmo_sec;
	tv.tv_usec = soe->so_rcv_tmo_usec;
	ret |= restore_opt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv);

	ret |= restore_bound_dev(sk, soe);
	ret |= restore_socket_filter(sk, soe);

	/* The restore of SO_REUSEADDR depends on type of socket */

	return ret;
}

int do_dump_opt(int sk, int level, int name, void *val, int len)
{
	socklen_t aux = len;

	if (getsockopt(sk, level, name, val, &aux) < 0) {
		pr_perror("Can't get %d:%d opt", level, name);
		return -1;
	}

	if (aux != len) {
		pr_err("Len mismatch on %d:%d : %d, want %d\n",
				level, name, aux, len);
		return -1;
	}

	return 0;
}

int dump_socket_opts(int sk, SkOptsEntry *soe)
{
	int ret = 0, val;
	struct timeval tv;

	ret |= dump_opt(sk, SOL_SOCKET, SO_SNDBUF, &soe->so_sndbuf);
	ret |= dump_opt(sk, SOL_SOCKET, SO_RCVBUF, &soe->so_rcvbuf);
	soe->has_so_priority = true;
	ret |= dump_opt(sk, SOL_SOCKET, SO_PRIORITY, &soe->so_priority);
	soe->has_so_rcvlowat = true;
	ret |= dump_opt(sk, SOL_SOCKET, SO_RCVLOWAT, &soe->so_rcvlowat);
	soe->has_so_mark = true;
	ret |= dump_opt(sk, SOL_SOCKET, SO_MARK, &soe->so_mark);

	ret |= dump_opt(sk, SOL_SOCKET, SO_SNDTIMEO, &tv);
	soe->so_snd_tmo_sec = tv.tv_sec;
	soe->so_snd_tmo_usec = tv.tv_usec;

	ret |= dump_opt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv);
	soe->so_rcv_tmo_sec = tv.tv_sec;
	soe->so_rcv_tmo_usec = tv.tv_usec;

	ret |= dump_opt(sk, SOL_SOCKET, SO_REUSEADDR, &val);
	soe->reuseaddr = val ? true : false;
	soe->has_reuseaddr = true;

	ret |= dump_opt(sk, SOL_SOCKET, SO_PASSCRED, &val);
	soe->has_so_passcred = true;
	soe->so_passcred = val ? true : false;

	ret |= dump_opt(sk, SOL_SOCKET, SO_PASSSEC, &val);
	soe->has_so_passsec = true;
	soe->so_passsec = val ? true : false;

	ret |= dump_opt(sk, SOL_SOCKET, SO_DONTROUTE, &val);
	soe->has_so_dontroute = true;
	soe->so_dontroute = val ? true : false;

	ret |= dump_opt(sk, SOL_SOCKET, SO_NO_CHECK, &val);
	soe->has_so_no_check = true;
	soe->so_no_check = val ? true : false;

	ret |= dump_bound_dev(sk, soe);
	ret |= dump_socket_filter(sk, soe);

	return ret;
}

void release_skopts(SkOptsEntry *soe)
{
	xfree(soe->so_filter);
	xfree(soe->so_bound_dev);
}

int dump_socket(struct fd_parms *p, int lfd, const int fdinfo)
{
	int family;
	const struct fdtype_ops *ops;

	if (dump_opt(lfd, SOL_SOCKET, SO_DOMAIN, &family))
		return -1;

	switch (family) {
	case AF_UNIX:
		ops = &unix_dump_ops;
		break;
	case AF_INET:
		ops = &inet_dump_ops;
		break;
	case AF_INET6:
		ops = &inet6_dump_ops;
		break;
	case AF_PACKET:
		ops = &packet_dump_ops;
		break;
	case AF_NETLINK:
		ops = &netlink_dump_ops;
		break;
	default:
		pr_err("BUG! Unknown socket collected (family %d)\n", family);
		return -1;
	}

	return do_dump_gen_file(p, lfd, ops, fdinfo);
}

static int inet_receive_one(struct nlmsghdr *h, void *arg)
{
	struct inet_diag_req_v2 *i = arg;
	int type;

	switch (i->sdiag_protocol) {
	case IPPROTO_TCP:
		type = SOCK_STREAM;
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		type = SOCK_DGRAM;
		break;
	default:
		BUG_ON(1);
		return -1;
	}

	return inet_collect_one(h, i->sdiag_family, type);
}

struct sock_diag_req {
	struct nlmsghdr hdr;
	union {
		struct unix_diag_req	u;
		struct inet_diag_req_v2	i;
		struct packet_diag_req	p;
		struct netlink_diag_req n;
	} r;
};

static int do_collect_req(int nl, struct sock_diag_req *req, int size,
		int (*receive_callback)(struct nlmsghdr *h, void *), void *arg)
{
	int tmp;

	tmp = do_rtnl_req(nl, req, size, receive_callback, arg);

	if (tmp == 0)
		set_collect_bit(req->r.n.sdiag_family, req->r.n.sdiag_protocol);

	return tmp;
}

int collect_sockets(int pid)
{
	int err = 0, tmp;
	int rst = -1;
	int nl;
	struct sock_diag_req req;

	if (current_ns_mask & CLONE_NEWNET) {
		pr_info("Switching to %d's net for collecting sockets\n", pid);

		if (switch_ns(pid, &net_ns_desc, &rst))
			return -1;
	}

	nl = socket(PF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
	if (nl < 0) {
		pr_perror("Can't create sock diag socket");
		err = -1;
		goto out;
	}

	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_len	= sizeof(req);
	req.hdr.nlmsg_type	= SOCK_DIAG_BY_FAMILY;
	req.hdr.nlmsg_flags	= NLM_F_DUMP | NLM_F_REQUEST;
	req.hdr.nlmsg_seq	= CR_NLMSG_SEQ;

	/* Collect UNIX sockets */
	req.r.u.sdiag_family	= AF_UNIX;
	req.r.u.udiag_states	= -1; /* All */
	req.r.u.udiag_show	= UDIAG_SHOW_NAME | UDIAG_SHOW_VFS |
				  UDIAG_SHOW_PEER | UDIAG_SHOW_ICONS |
				  UDIAG_SHOW_RQLEN;
	tmp = do_collect_req(nl, &req, sizeof(req), unix_receive_one, NULL);
	if (tmp)
		err = tmp;

	/* Collect IPv4 TCP sockets */
	req.r.i.sdiag_family	= AF_INET;
	req.r.i.sdiag_protocol	= IPPROTO_TCP;
	req.r.i.idiag_ext	= 0;
	/* Only listening and established sockets supported yet */
	req.r.i.idiag_states	= (1 << TCP_LISTEN) | (1 << TCP_ESTABLISHED);
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv4 UDP sockets */
	req.r.i.sdiag_family	= AF_INET;
	req.r.i.sdiag_protocol	= IPPROTO_UDP;
	req.r.i.idiag_ext	= 0;
	req.r.i.idiag_states	= -1; /* All */
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv4 UDP-lite sockets */
	req.r.i.sdiag_family	= AF_INET;
	req.r.i.sdiag_protocol	= IPPROTO_UDPLITE;
	req.r.i.idiag_ext	= 0;
	req.r.i.idiag_states	= -1; /* All */
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv6 TCP sockets */
	req.r.i.sdiag_family	= AF_INET6;
	req.r.i.sdiag_protocol	= IPPROTO_TCP;
	req.r.i.idiag_ext	= 0;
	/* Only listening sockets supported yet */
	req.r.i.idiag_states	= (1 << TCP_LISTEN) | (1 << TCP_ESTABLISHED);
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv6 UDP sockets */
	req.r.i.sdiag_family	= AF_INET6;
	req.r.i.sdiag_protocol	= IPPROTO_UDP;
	req.r.i.idiag_ext	= 0;
	req.r.i.idiag_states	= -1; /* All */
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv6 UDP-lite sockets */
	req.r.i.sdiag_family	= AF_INET6;
	req.r.i.sdiag_protocol	= IPPROTO_UDPLITE;
	req.r.i.idiag_ext	= 0;
	req.r.i.idiag_states	= -1; /* All */
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, &req.r.i);
	if (tmp)
		err = tmp;

	req.r.p.sdiag_family	= AF_PACKET;
	req.r.p.sdiag_protocol	= 0;
	req.r.p.pdiag_show	= PACKET_SHOW_INFO | PACKET_SHOW_MCLIST |
					PACKET_SHOW_FANOUT | PACKET_SHOW_RING_CFG;
	tmp = do_collect_req(nl, &req, sizeof(req), packet_receive_one, NULL);
	if (tmp) {
		pr_warn("The current kernel doesn't support packet_diag\n");
		if (pid == 0 || tmp != -ENOENT) /* Fedora 19 */
			err = tmp;
	}

	req.r.n.sdiag_family	= AF_NETLINK;
	req.r.n.sdiag_protocol	= NDIAG_PROTO_ALL;
	req.r.n.ndiag_show	= NDIAG_SHOW_GROUPS;
	tmp = do_collect_req(nl, &req, sizeof(req), netlink_receive_one, NULL);
	if (tmp) {
		pr_warn("The current kernel doesn't support netlink_diag\n");
		if (pid == 0 || tmp != -ENOENT) /* Fedora 19 */
			err = tmp;
	}

	close(nl);
out:
	if (rst >= 0) {
		if (restore_ns(rst, &net_ns_desc) < 0)
			err = -1;
	} else if (pid != 0) {
		/*
		 * If netns isn't dumped, criu will fail only
		 * if an unsupported socket will be really dumped.
		 */
		pr_info("Uncollected sockets! Will probably fail later.\n");
		err = 0;
	}

	return err;
}

static inline char *unknown(u32 val)
{
	static char unk[12];
	snprintf(unk, sizeof(unk), "x%d", val);
	return unk;
}

char *skfamily2s(u32 f)
{
	if (f == AF_INET)
		return " inet";
	else if (f == AF_INET6)
		return "inet6";
	else
		return unknown(f);
}

char *sktype2s(u32 t)
{
	if (t == SOCK_STREAM)
		return "stream";
	else if (t == SOCK_DGRAM)
		return " dgram";
	else
		return unknown(t);
}

char *skproto2s(u32 p)
{
	if (p == IPPROTO_UDP)
		return "udp";
	else if (p == IPPROTO_UDPLITE)
		return "udpl";
	else if (p == IPPROTO_TCP)
		return "tcp";
	else
		return unknown(p);
}

char *skstate2s(u32 state)
{
	if (state == TCP_ESTABLISHED)
		return " estab";
	else if (state == TCP_CLOSE)
		return "closed";
	else if (state == TCP_LISTEN)
		return "listen";
	else
		return unknown(state);
}
