#include <sched.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/filter.h>
#include <string.h>
#include <netinet/in.h>

#include "int.h"
#include "bitops.h"
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
#include "lsm.h"
#include "net.h"
#include "xmalloc.h"
#include "fs-magic.h"
#include "pstree.h"
#include "util.h"
#include "fdstore.h"
#include "cr_options.h"

#undef LOG_PREFIX
#define LOG_PREFIX "sockets: "

#ifndef SOCK_DIAG_BY_FAMILY
#define SOCK_DIAG_BY_FAMILY 20
#endif

#define SK_HASH_SIZE (1 << 14)

#ifndef SO_GET_FILTER
#define SO_GET_FILTER SO_ATTACH_FILTER
#endif

static const char *__socket_const_name(char *dst, size_t len, const char **a, size_t n, unsigned int v)
{
	if (v < n) {
		const char *name = a[v];
		if (name)
			return name;
	}
	snprintf(dst, len, "%u", v);
	return dst;
}

const char *socket_proto_name(unsigned int proto, char *nm, size_t size)
{
	static const char *protos[] = {
		[IPPROTO_IP] = __stringify_1(IPPROTO_IP),     [IPPROTO_ICMP] = __stringify_1(IPPROTO_ICMP),
		[IPPROTO_IGMP] = __stringify_1(IPPROTO_IGMP), [IPPROTO_IPIP] = __stringify_1(IPPROTO_IPIP),
		[IPPROTO_TCP] = __stringify_1(IPPROTO_TCP),   [IPPROTO_EGP] = __stringify_1(IPPROTO_EGP),
		[IPPROTO_UDP] = __stringify_1(IPPROTO_UDP),   [IPPROTO_DCCP] = __stringify_1(IPPROTO_DCCP),
		[IPPROTO_IPV6] = __stringify_1(IPPROTO_IPV6), [IPPROTO_RSVP] = __stringify_1(IPPROTO_RSVP),
		[IPPROTO_GRE] = __stringify_1(IPPROTO_GRE),   [IPPROTO_ESP] = __stringify_1(IPPROTO_ESP),
		[IPPROTO_AH] = __stringify_1(IPPROTO_AH),     [IPPROTO_UDPLITE] = __stringify_1(IPPROTO_UDPLITE),
		[IPPROTO_RAW] = __stringify_1(IPPROTO_RAW),
	};
	return __socket_const_name(nm, size, protos, ARRAY_SIZE(protos), proto);
}

const char *socket_family_name(unsigned int family, char *nm, size_t size)
{
	static const char *families[] = {
		[AF_UNIX] = __stringify_1(AF_UNIX),	[AF_INET] = __stringify_1(AF_INET),
		[AF_BRIDGE] = __stringify_1(AF_BRIDGE), [AF_INET6] = __stringify_1(AF_INET6),
		[AF_KEY] = __stringify_1(AF_KEY),	[AF_NETLINK] = __stringify_1(AF_NETLINK),
		[AF_PACKET] = __stringify_1(AF_PACKET),
	};
	return __socket_const_name(nm, size, families, ARRAY_SIZE(families), family);
}

const char *socket_type_name(unsigned int type, char *nm, size_t size)
{
	static const char *types[] = {
		[SOCK_STREAM] = __stringify_1(SOCK_STREAM), [SOCK_DGRAM] = __stringify_1(SOCK_DGRAM),
		[SOCK_RAW] = __stringify_1(SOCK_RAW),	    [SOCK_SEQPACKET] = __stringify_1(SOCK_SEQPACKET),
		[SOCK_PACKET] = __stringify_1(SOCK_PACKET),
	};
	return __socket_const_name(nm, size, types, ARRAY_SIZE(types), type);
}

const char *tcp_state_name(unsigned int state, char *nm, size_t size)
{
	static const char *states[] = {
		[TCP_ESTABLISHED] = __stringify_1(TCP_ESTABLISHED),
		[TCP_SYN_SENT] = __stringify_1(TCP_SYN_SENT),
		[TCP_SYN_RECV] = __stringify_1(TCP_SYN_RECV),
		[TCP_FIN_WAIT1] = __stringify_1(TCP_FIN_WAIT1),
		[TCP_FIN_WAIT2] = __stringify_1(TCP_FIN_WAIT2),
		[TCP_TIME_WAIT] = __stringify_1(TCP_TIME_WAIT),
		[TCP_CLOSE] = __stringify_1(TCP_CLOSE),
		[TCP_CLOSE_WAIT] = __stringify_1(TCP_CLOSE_WAIT),
		[TCP_LAST_ACK] = __stringify_1(TCP_LAST_ACK),
		[TCP_LISTEN] = __stringify_1(TCP_LISTEN),
		[TCP_CLOSING] = __stringify_1(TCP_CLOSING),
	};
	return __socket_const_name(nm, size, states, ARRAY_SIZE(states), state);
}

struct sock_diag_greq {
	u8 family;
	u8 protocol;
};

struct sock_diag_req {
	struct nlmsghdr hdr;
	union {
		struct unix_diag_req u;
		struct inet_diag_req_v2 i;
		struct packet_diag_req p;
		struct netlink_diag_req n;
		struct sock_diag_greq g;
	} r;
};

enum socket_cl_bits {
	NETLINK_CL_BIT,
	INET_TCP_CL_BIT,
	INET_UDP_CL_BIT,
	INET_UDPLITE_CL_BIT,
	INET_RAW_CL_BIT,
	INET6_TCP_CL_BIT,
	INET6_UDP_CL_BIT,
	INET6_UDPLITE_CL_BIT,
	INET6_RAW_CL_BIT,
	UNIX_CL_BIT,
	PACKET_CL_BIT,
	_MAX_CL_BIT,
};

#define MAX_CL_BIT (_MAX_CL_BIT - 1)

static DECLARE_BITMAP(socket_cl_bits, MAX_CL_BIT);

static inline enum socket_cl_bits get_collect_bit_nr(unsigned int family, unsigned int proto)
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
		if (proto == IPPROTO_RAW)
			return INET_RAW_CL_BIT;
	}
	if (family == AF_INET6) {
		if (proto == IPPROTO_TCP)
			return INET6_TCP_CL_BIT;
		if (proto == IPPROTO_UDP)
			return INET6_UDP_CL_BIT;
		if (proto == IPPROTO_UDPLITE)
			return INET6_UDPLITE_CL_BIT;
		if (proto == IPPROTO_RAW)
			return INET6_RAW_CL_BIT;
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

static int probe_recv_one(struct nlmsghdr *h, struct ns_id *ns, void *arg)
{
	pr_err("PROBE RECEIVED\n");
	return -1;
}

static int probe_err(int err, struct ns_id *ns, void *arg)
{
	int expected_err = *(int *)arg;

	if (err == expected_err)
		return 0;

	pr_err("Diag module missing (%d)\n", err);
	return err;
}

static inline void probe_diag(int nl, struct sock_diag_req *req, int expected_err)
{
	do_rtnl_req(nl, req, req->hdr.nlmsg_len, probe_recv_one, probe_err, NULL, &expected_err);
}

void preload_socket_modules(void)
{
	int nl;
	struct sock_diag_req req;

	/*
	 * If the task to dump (e.g. an LXC container) has any netlink
	 * KOBJECT_UEVENT socket open and the _diag modules aren't
	 * loaded is dumped, criu will freeze the task and then the
	 * kernel will send it messages on the socket, and then we will
	 * fail to dump because the socket has pending data. The Real
	 * Solution is to dump this pending data, but we just make sure
	 * modules are there beforehand for now so that the first dump
	 * doesn't fail.
	 */

	nl = socket(PF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
	if (nl < 0)
		return;

	pr_info("Probing sock diag modules\n");

	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_type = SOCK_DIAG_BY_FAMILY;
	req.hdr.nlmsg_seq = CR_NLMSG_SEQ;

	/*
	 * Probe UNIX, netlink and packet diag-s by feeding
	 * to the kernel request that is shorter than they
	 * expect, byt still containing the family to make
	 * sure the family handler is there. The family-level
	 * diag module would report EINVAL in this case.
	 */

	req.hdr.nlmsg_len = sizeof(req.hdr) + sizeof(req.r.g);
	req.hdr.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;

	req.r.g.family = AF_UNIX;
	probe_diag(nl, &req, -EINVAL);

	req.r.g.family = AF_PACKET;
	probe_diag(nl, &req, -EINVAL);

	req.r.g.family = AF_NETLINK;
	probe_diag(nl, &req, -EINVAL);

	/*
	 * TCP and UDP(LITE) diags do not support such trick, only
	 * inet_diag module can be probed like that. For the protocol
	 * level ones it's OK to request for exact non-existing socket
	 * and check for ENOENT being reported back as error.
	 */

	req.hdr.nlmsg_len = sizeof(req.hdr) + sizeof(req.r.i);
	req.hdr.nlmsg_flags = NLM_F_REQUEST;
	req.r.i.sdiag_family = AF_INET;

	req.r.i.sdiag_protocol = IPPROTO_TCP;
	probe_diag(nl, &req, -ENOENT);

	req.r.i.sdiag_protocol = IPPROTO_UDP; /* UDLITE is merged with UDP */
	probe_diag(nl, &req, -ENOENT);

	req.r.i.sdiag_protocol = IPPROTO_RAW;
	probe_diag(nl, &req, -ENOENT);

	close(nl);
	pr_info("Done probing\n");
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

static void encode_filter(struct sock_filter *f, u64 *img, int n)
{
	int i;

	BUILD_BUG_ON(sizeof(*f) != sizeof(*img));

	for (i = 0; i < n; i++)
		img[i] = ((u64)f[i].code << 48) | ((u64)f[i].jt << 40) | ((u64)f[i].jf << 32) | ((u64)f[i].k << 0);
}

static void decode_filter(u64 *img, struct sock_filter *f, int n)
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
	sfp.filter = xmalloc(sfp.len * sizeof(struct sock_filter));
	if (!sfp.filter)
		return -1;

	decode_filter(soe->so_filter, sfp.filter, sfp.len);
	ret = restore_opt(sk, SOL_SOCKET, SO_ATTACH_FILTER, &sfp);
	if (ret)
		pr_err("Can't restore filter\n");

	xfree(sfp.filter);

	return ret;
}

static struct socket_desc *sockets[SK_HASH_SIZE];

struct socket_desc *lookup_socket_ino(unsigned int ino, int family)
{
	struct socket_desc *sd;

	pr_debug("Searching for socket %#x family %d\n", ino, family);

	for (sd = sockets[ino % SK_HASH_SIZE]; sd; sd = sd->next) {
		if (sd->ino == ino) {
			BUG_ON(sd->family != family);
			return sd;
		}
	}

	return NULL;
}

struct socket_desc *lookup_socket(unsigned int ino, int family, int proto)
{
	if (!socket_test_collect_bit(family, proto)) {
		pr_err("Sockets (family %d proto %d) are not collected\n", family, proto);
		return ERR_PTR(-EINVAL);
	}

	return lookup_socket_ino(ino, family);
}

int sk_collect_one(unsigned ino, int family, struct socket_desc *d, struct ns_id *ns)
{
	struct socket_desc **chain;

	d->ino = ino;
	d->family = family;
	d->already_dumped = 0;
	d->sk_ns = ns;

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

int sk_setbufs(int sk, uint32_t *bufs)
{
	uint32_t sndbuf = bufs[0], rcvbuf = bufs[1];

	if (setsockopt(sk, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf)) ||
	    setsockopt(sk, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf))) {
		if (opts.unprivileged) {
			pr_info("Unable to set SO_SNDBUFFORCE/SO_RCVBUFFORCE, falling back to SO_SNDBUF/SO_RCVBUF\n");
			if (setsockopt(sk, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) ||
			    setsockopt(sk, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf))) {
				pr_perror("Unable to set socket SO_SNDBUF/SO_RCVBUF");
				return -1;
			}
		} else {
			pr_perror("Unable to set socket SO_SNDBUFFORCE/SO_RCVBUFFORCE");
			return -1;
		}
	}

	return 0;
}

static int sk_setbufs_ns(void *arg, int fd, pid_t pid)
{
	return sk_setbufs(fd, (uint32_t *)arg);
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
	u32 maxbuf[2] = { INT_MAX / 2, INT_MAX / 2 };

	if (userns_call(sk_setbufs_ns, 0, maxbuf, sizeof(maxbuf), sk))
		return -1;

	/* Prevent blocking on restore */
	flags = fcntl(sk, F_GETFL, 0);
	if (flags == -1) {
		pr_perror("Unable to get flags for %d", sk);
		return -1;
	}
	if (fcntl(sk, F_SETFL, flags | O_NONBLOCK)) {
		pr_perror("Unable to set O_NONBLOCK for %d", sk);
		return -1;
	}

	return 0;
}

int restore_socket_opts(int sk, SkOptsEntry *soe)
{
	int ret = 0, val = 1;
	struct timeval tv;
	struct linger so_linger;
	/* In kernel a bufsize value is doubled. */
	u32 bufs[2] = { soe->so_sndbuf / 2, soe->so_rcvbuf / 2 };

	pr_info("%d restore sndbuf %d rcv buf %d\n", sk, soe->so_sndbuf, soe->so_rcvbuf);

	/* setsockopt() multiplies the input values by 2 */
	ret |= userns_call(sk_setbufs_ns, 0, bufs, sizeof(bufs), sk);

	if (soe->has_so_buf_lock) {
		pr_debug("\trestore buf_lock %d for socket\n", soe->so_buf_lock);
		ret |= restore_opt(sk, SOL_SOCKET, SO_BUF_LOCK, &soe->so_buf_lock);
	}
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
		pr_debug("\tset passcred for socket\n");
		ret |= restore_opt(sk, SOL_SOCKET, SO_PASSCRED, &val);
	}
	if (soe->has_so_passsec && soe->so_passsec) {
		pr_debug("\tset passsec for socket\n");
		ret |= restore_opt(sk, SOL_SOCKET, SO_PASSSEC, &val);
	}
	if (soe->has_so_dontroute && soe->so_dontroute) {
		pr_debug("\tset dontroute for socket\n");
		ret |= restore_opt(sk, SOL_SOCKET, SO_DONTROUTE, &val);
	}
	if (soe->has_so_no_check && soe->so_no_check) {
		pr_debug("\tset no_check for socket\n");
		ret |= restore_opt(sk, SOL_SOCKET, SO_NO_CHECK, &val);
	}
	if (soe->has_so_broadcast && soe->so_broadcast) {
		pr_debug("\tset broadcast for socket\n");
		ret |= restore_opt(sk, SOL_SOCKET, SO_BROADCAST, &val);
	}
	if (soe->has_so_oobinline && soe->so_oobinline) {
		pr_debug("\tset oobinline for socket\n");
		ret |= restore_opt(sk, SOL_SOCKET, SO_OOBINLINE, &val);
	}
	if (soe->has_so_linger) {
		pr_debug("\tset so_linger for socket\n");
		so_linger.l_onoff = true;
		so_linger.l_linger = soe->so_linger;
		ret |= restore_opt(sk, SOL_SOCKET, SO_LINGER, &so_linger);
	}
	if (soe->has_so_keepalive && soe->so_keepalive) {
		pr_debug("\tset keepalive for socket\n");
		ret |= restore_opt(sk, SOL_SOCKET, SO_KEEPALIVE, &val);
	}
	if (soe->has_tcp_keepcnt) {
		pr_debug("\tset keepcnt for socket\n");
		ret |= restore_opt(sk, SOL_TCP, TCP_KEEPCNT, &soe->tcp_keepcnt);
	}
	if (soe->has_tcp_keepidle) {
		pr_debug("\tset keepidle for socket\n");
		ret |= restore_opt(sk, SOL_TCP, TCP_KEEPIDLE, &soe->tcp_keepidle);
	}
	if (soe->has_tcp_keepintvl) {
		pr_debug("\tset keepintvl for socket\n");
		ret |= restore_opt(sk, SOL_TCP, TCP_KEEPINTVL, &soe->tcp_keepintvl);
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
		pr_err("Len mismatch on %d:%d : %d, want %d\n", level, name, aux, len);
		return -1;
	}

	return 0;
}

int dump_socket_opts(int sk, SkOptsEntry *soe)
{
	int ret = 0, val;
	struct timeval tv;
	struct linger so_linger = { 0, 0 };

	ret |= dump_opt(sk, SOL_SOCKET, SO_SNDBUF, &soe->so_sndbuf);
	ret |= dump_opt(sk, SOL_SOCKET, SO_RCVBUF, &soe->so_rcvbuf);
	if (kdat.has_sockopt_buf_lock) {
		soe->has_so_buf_lock = true;
		ret |= dump_opt(sk, SOL_SOCKET, SO_BUF_LOCK, &soe->so_buf_lock);
	}
	soe->has_so_priority = true;
	ret |= dump_opt(sk, SOL_SOCKET, SO_PRIORITY, &soe->so_priority);
	soe->has_so_rcvlowat = true;
	ret |= dump_opt(sk, SOL_SOCKET, SO_RCVLOWAT, &soe->so_rcvlowat);
	/*
	 * Restoring SO_MARK requires root or CAP_NET_ADMIN. Avoid saving it
	 * in unprivileged mode if still has its default value.
	 */
	ret |= dump_opt(sk, SOL_SOCKET, SO_MARK, &soe->so_mark);
	soe->has_so_mark = !!soe->so_mark;

	ret |= dump_opt(sk, SOL_SOCKET, SO_SNDTIMEO, &tv);
	soe->so_snd_tmo_sec = tv.tv_sec;
	soe->so_snd_tmo_usec = tv.tv_usec;

	ret |= dump_opt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv);
	soe->so_rcv_tmo_sec = tv.tv_sec;
	soe->so_rcv_tmo_usec = tv.tv_usec;

	ret |= dump_opt(sk, SOL_SOCKET, SO_REUSEADDR, &val);
	soe->reuseaddr = val ? true : false;
	soe->has_reuseaddr = true;

	ret |= dump_opt(sk, SOL_SOCKET, SO_REUSEPORT, &val);
	soe->so_reuseport = val ? true : false;
	soe->has_so_reuseport = true;

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

	ret |= dump_opt(sk, SOL_SOCKET, SO_BROADCAST, &val);
	soe->has_so_broadcast = true;
	soe->so_broadcast = val ? true : false;

	ret |= dump_opt(sk, SOL_SOCKET, SO_KEEPALIVE, &val);
	soe->has_so_keepalive = true;
	soe->so_keepalive = val ? true : false;

	ret |= dump_opt(sk, SOL_SOCKET, SO_OOBINLINE, &val);
	soe->has_so_oobinline = true;
	soe->so_oobinline = val ? true : false;

	ret |= dump_opt(sk, SOL_SOCKET, SO_LINGER, &so_linger);
	if (so_linger.l_onoff) {
		soe->has_so_linger = true;
		soe->so_linger = so_linger.l_linger;
	}

	ret |= dump_bound_dev(sk, soe);
	ret |= dump_socket_filter(sk, soe);

	return ret;
}

void release_skopts(SkOptsEntry *soe)
{
	xfree(soe->so_filter);
	xfree(soe->so_bound_dev);
}

int dump_socket(struct fd_parms *p, int lfd, FdinfoEntry *e)
{
	int family;
	const struct fdtype_ops *ops;

	if (dump_xattr_security_selinux(lfd, e))
		return -1;

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

	return do_dump_gen_file(p, lfd, ops, e);
}

static int inet_receive_one(struct nlmsghdr *h, struct ns_id *ns, void *arg)
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
	case IPPROTO_RAW:
		type = SOCK_RAW;
		break;
	default:
		BUG_ON(1);
		return -1;
	}

	return inet_collect_one(h, i->sdiag_family, type, ns);
}

static int do_collect_req(int nl, struct sock_diag_req *req, int size,
			  int (*receive_callback)(struct nlmsghdr *h, struct ns_id *ns, void *),
			  int (*error_callback)(int err, struct ns_id *ns, void *), struct ns_id *ns, void *arg)
{
	int tmp = do_rtnl_req(nl, req, size, receive_callback, error_callback, ns, arg);
	if (tmp == 0)
		set_collect_bit(req->r.n.sdiag_family, req->r.n.sdiag_protocol);
	return tmp;
}

static int collect_err(int err, struct ns_id *ns, void *arg)
{
	struct sock_diag_greq *gr = arg;
	char family[32], proto[32];
	char msg[256];

	snprintf(msg, sizeof(msg), "Sockects collect procedure family %s proto %s",
		 socket_family_name(gr->family, family, sizeof(family)),
		 socket_proto_name(gr->protocol, proto, sizeof(proto)));

	/*
	 * If module is not compiled or unloaded,
	 * we should simply pass error up to a caller
	 * which then warn a user.
	 */
	if (err == -ENOENT) {
		pr_debug("%s: %d\n", msg, err);
		/*
		 * Unlike other modules RAW sockets are
		 * always optional and not commonly used.
		 * Currently we warn user about lack of
		 * a particular module support in "check"
		 * procedure. Thus don't fail on lack of
		 * RAW diags in a regular dump. If we meet
		 * a raw socket we will simply fail on dump
		 * procedure because it won't be resolved.
		 */
		if (gr->protocol == IPPROTO_RAW)
			return 0;
		return -ENOENT;
	}

	/*
	 * Diag modules such as unix, packet, netlink
	 * may return EINVAL on older kernels.
	 */
	if (err == -EINVAL) {
		if (gr->family == AF_UNIX || gr->family == AF_PACKET || gr->family == AF_NETLINK) {
			pr_debug("%s: %d\n", msg, err);
			return -EINVAL;
		}
	}

	/*
	 * Rest is more serious, just print enough information.
	 * In case if everything is OK -- point as well.
	 */
	if (!err)
		pr_info("%s: OK\n", msg);
	else
		pr_err("%s: %d: %s\n", msg, err, strerror(-err));

	return err;
}

int collect_sockets(struct ns_id *ns)
{
	int err = 0, tmp;
	int nl = ns->net.nlsk;
	struct sock_diag_req req;

	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_len = sizeof(req);
	req.hdr.nlmsg_type = SOCK_DIAG_BY_FAMILY;
	req.hdr.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	req.hdr.nlmsg_seq = CR_NLMSG_SEQ;

	/* Collect UNIX sockets */
	req.r.u.sdiag_family = AF_UNIX;
	req.r.u.udiag_states = -1; /* All */
	req.r.u.udiag_show = UDIAG_SHOW_NAME | UDIAG_SHOW_VFS | UDIAG_SHOW_PEER | UDIAG_SHOW_ICONS | UDIAG_SHOW_RQLEN;
	tmp = do_collect_req(nl, &req, sizeof(req), unix_receive_one, collect_err, ns, &req.r.u);
	if (tmp)
		err = tmp;

	/* Collect IPv4 TCP sockets */
	req.r.i.sdiag_family = AF_INET;
	req.r.i.sdiag_protocol = IPPROTO_TCP;
	req.r.i.idiag_ext = 0;
	/* Only listening and established sockets supported yet */
	req.r.i.idiag_states = (1 << TCP_LISTEN) | (1 << TCP_ESTABLISHED) | (1 << TCP_FIN_WAIT1) |
			       (1 << TCP_FIN_WAIT2) | (1 << TCP_CLOSE_WAIT) | (1 << TCP_LAST_ACK) | (1 << TCP_CLOSING) |
			       (1 << TCP_SYN_SENT);
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, collect_err, ns, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv4 UDP sockets */
	req.r.i.sdiag_family = AF_INET;
	req.r.i.sdiag_protocol = IPPROTO_UDP;
	req.r.i.idiag_ext = 0;
	req.r.i.idiag_states = -1; /* All */
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, collect_err, ns, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv4 UDP-lite sockets */
	req.r.i.sdiag_family = AF_INET;
	req.r.i.sdiag_protocol = IPPROTO_UDPLITE;
	req.r.i.idiag_ext = 0;
	req.r.i.idiag_states = -1; /* All */
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, collect_err, ns, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv4 RAW sockets */
	req.r.i.sdiag_family = AF_INET;
	req.r.i.sdiag_protocol = IPPROTO_RAW;
	req.r.i.idiag_ext = 0;
	req.r.i.idiag_states = -1; /* All */
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, collect_err, ns, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv6 TCP sockets */
	req.r.i.sdiag_family = AF_INET6;
	req.r.i.sdiag_protocol = IPPROTO_TCP;
	req.r.i.idiag_ext = 0;
	/* Only listening sockets supported yet */
	req.r.i.idiag_states = (1 << TCP_LISTEN) | (1 << TCP_ESTABLISHED) | (1 << TCP_FIN_WAIT1) |
			       (1 << TCP_FIN_WAIT2) | (1 << TCP_CLOSE_WAIT) | (1 << TCP_LAST_ACK) | (1 << TCP_CLOSING) |
			       (1 << TCP_SYN_SENT);
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, collect_err, ns, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv6 UDP sockets */
	req.r.i.sdiag_family = AF_INET6;
	req.r.i.sdiag_protocol = IPPROTO_UDP;
	req.r.i.idiag_ext = 0;
	req.r.i.idiag_states = -1; /* All */
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, collect_err, ns, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv6 UDP-lite sockets */
	req.r.i.sdiag_family = AF_INET6;
	req.r.i.sdiag_protocol = IPPROTO_UDPLITE;
	req.r.i.idiag_ext = 0;
	req.r.i.idiag_states = -1; /* All */
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, collect_err, ns, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv6 RAW sockets */
	req.r.i.sdiag_family = AF_INET6;
	req.r.i.sdiag_protocol = IPPROTO_RAW;
	req.r.i.idiag_ext = 0;
	req.r.i.idiag_states = -1; /* All */
	tmp = do_collect_req(nl, &req, sizeof(req), inet_receive_one, collect_err, ns, &req.r.i);
	if (tmp)
		err = tmp;

	req.r.p.sdiag_family = AF_PACKET;
	req.r.p.sdiag_protocol = 0;
	req.r.p.pdiag_show = PACKET_SHOW_INFO | PACKET_SHOW_MCLIST | PACKET_SHOW_FANOUT | PACKET_SHOW_RING_CFG;
	tmp = do_collect_req(nl, &req, sizeof(req), packet_receive_one, collect_err, ns, &req.r.p);
	if (tmp)
		err = tmp;

	req.r.n.sdiag_family = AF_NETLINK;
	req.r.n.sdiag_protocol = NDIAG_PROTO_ALL;
	req.r.n.ndiag_show = NDIAG_SHOW_GROUPS;
	tmp = do_collect_req(nl, &req, sizeof(req), netlink_receive_one, collect_err, ns, &req.r.n);
	if (tmp)
		err = tmp;

	/* don't need anymore */
	close(nl);
	ns->net.nlsk = -1;

	if (err && (ns->type == NS_CRIU)) {
		/*
		 * If netns isn't dumped, criu will fail only
		 * if an unsupported socket will be really dumped.
		 */
		pr_info("Uncollected sockets! Will probably fail later.\n");
		err = 0;
	}

	return err;
}

static uint32_t last_ns_id = 0;

int set_netns(uint32_t ns_id)
{
	struct ns_id *ns;
	int nsfd;

	if (!(root_ns_mask & CLONE_NEWNET))
		return 0;

	if (ns_id == last_ns_id)
		return 0;

	/*
	 * The 0 ns_id means that it was not set. We need
	 * this to be compatible with old images.
	 */
	if (ns_id == 0)
		ns = net_get_root_ns();
	else
		ns = lookup_ns_by_id(ns_id, &net_ns_desc);
	if (ns == NULL) {
		pr_err("Unable to find a network namespace\n");
		return -1;
	}
	nsfd = fdstore_get(ns->net.nsfd_id);
	if (nsfd < 0)
		return -1;
	if (setns(nsfd, CLONE_NEWNET)) {
		pr_perror("Unable to switch a network namespace");
		close(nsfd);
		return -1;
	}
	last_ns_id = ns_id;
	close(nsfd);

	return 0;
}
