#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <linux/net.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <sys/sendfile.h>

#include "types.h"
#include "libnetlink.h"
#include "sockets.h"
#include "sk-queue.h"
#include "unix_diag.h"
#include "image.h"
#include "crtools.h"
#include "util.h"
#include "inet_diag.h"
#include "files.h"
#include "util-net.h"

static char buf[4096];

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

static struct socket_desc *sockets[SK_HASH_SIZE];

struct socket_desc *lookup_socket(int ino)
{
	struct socket_desc *sd;

	for (sd = sockets[ino % SK_HASH_SIZE]; sd; sd = sd->next)
		if (sd->ino == ino)
			return sd;
	return NULL;
}

int sk_collect_one(int ino, int family, struct socket_desc *d)
{
	struct socket_desc **chain;

	d->ino		= ino;
	d->family	= family;

	chain = &sockets[ino % SK_HASH_SIZE];
	d->next = *chain;
	*chain = d;

	return 0;
}

int dump_socket(struct fd_parms *p, int lfd, const struct cr_fdset *cr_fdset)
{
	struct socket_desc *sk;

	sk = lookup_socket(p->stat.st_ino);
	if (!sk) {
		pr_err("Uncollected socket 0x%8x\n", (int)p->stat.st_ino);
		return -1;
	}

	switch (sk->family) {
	case AF_UNIX:
		return dump_one_unix(sk, p, lfd, cr_fdset);
	case AF_INET:
	case AF_INET6:
		return dump_one_inet(sk, p, cr_fdset);
	default:
		pr_err("BUG! Unknown socket collected\n");
		break;
	}

	return -1;
}

static int inet_tcp_receive_one(struct nlmsghdr *h)
{
	return inet_collect_one(h, AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

static int inet_udp_receive_one(struct nlmsghdr *h)
{
	return inet_collect_one(h, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

static int inet_udplite_receive_one(struct nlmsghdr *h)
{
	return inet_collect_one(h, AF_INET, SOCK_DGRAM, IPPROTO_UDPLITE);
}

static int inet6_tcp_receive_one(struct nlmsghdr *h)
{
	return inet_collect_one(h, AF_INET6, SOCK_STREAM, IPPROTO_TCP);
}

static int inet6_udp_receive_one(struct nlmsghdr *h)
{
	return inet_collect_one(h, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
}

static int inet6_udplite_receive_one(struct nlmsghdr *h)
{
	return inet_collect_one(h, AF_INET6, SOCK_DGRAM, IPPROTO_UDPLITE);
}

static int collect_sockets_nl(int nl, void *req, int size,
			      int (*receive_callback)(struct nlmsghdr *h))
{
	struct msghdr msg;
	struct sockaddr_nl nladdr;
	struct iovec iov;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name	= &nladdr;
	msg.msg_namelen	= sizeof(nladdr);
	msg.msg_iov	= &iov;
	msg.msg_iovlen	= 1;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family= AF_NETLINK;

	iov.iov_base	= req;
	iov.iov_len	= size;

	if (sendmsg(nl, &msg, 0) < 0) {
		pr_perror("Can't send request message");
		goto err;
	}

	iov.iov_base	= buf;
	iov.iov_len	= sizeof(buf);

	while (1) {
		int err;

		memset(&msg, 0, sizeof(msg));
		msg.msg_name	= &nladdr;
		msg.msg_namelen	= sizeof(nladdr);
		msg.msg_iov	= &iov;
		msg.msg_iovlen	= 1;

		err = recvmsg(nl, &msg, 0);
		if (err < 0) {
			if (errno == EINTR)
				continue;
			else {
				pr_perror("Error receiving nl report");
				goto err;
			}
		}
		if (err == 0)
			break;

		err = nlmsg_receive(buf, err, receive_callback);
		if (err < 0)
			goto err;
		if (err == 0)
			break;
	}

	return 0;

err:
	return -1;
}

int collect_sockets(void)
{
	int err = 0, tmp;
	int nl;
	int supp_type = 0;
	struct {
		struct nlmsghdr hdr;
		union {
			struct unix_diag_req	u;
			struct inet_diag_req_v2	i;
		} r;
	} req;

	nl = socket(PF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
	if (nl < 0) {
		pr_perror("Can't create sock diag socket");
		return -1;
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
	tmp = collect_sockets_nl(nl, &req, sizeof(req), unix_receive_one);
	if (tmp)
		err = tmp;

	/* Collect IPv4 TCP sockets */
	req.r.i.sdiag_family	= AF_INET;
	req.r.i.sdiag_protocol	= IPPROTO_TCP;
	req.r.i.idiag_ext	= 0;
	/* Only listening sockets supported yet */
	req.r.i.idiag_states	= 1 << TCP_LISTEN;
	tmp = collect_sockets_nl(nl, &req, sizeof(req), inet_tcp_receive_one);
	if (tmp)
		err = tmp;

	/* Collect IPv4 UDP sockets */
	req.r.i.sdiag_family	= AF_INET;
	req.r.i.sdiag_protocol	= IPPROTO_UDP;
	req.r.i.idiag_ext	= 0;
	req.r.i.idiag_states	= -1; /* All */
	tmp = collect_sockets_nl(nl, &req, sizeof(req), inet_udp_receive_one);
	if (tmp)
		err = tmp;

	/* Collect IPv4 UDP-lite sockets */
	req.r.i.sdiag_family	= AF_INET;
	req.r.i.sdiag_protocol	= IPPROTO_UDPLITE;
	req.r.i.idiag_ext	= 0;
	req.r.i.idiag_states	= -1; /* All */
	tmp = collect_sockets_nl(nl, &req, sizeof(req), inet_udplite_receive_one);
	if (tmp)
		err = tmp;

	/* Collect IPv6 TCP sockets */
	req.r.i.sdiag_family	= AF_INET6;
	req.r.i.sdiag_protocol	= IPPROTO_TCP;
	req.r.i.idiag_ext	= 0;
	/* Only listening sockets supported yet */
	req.r.i.idiag_states	= 1 << TCP_LISTEN;
	tmp = collect_sockets_nl(nl, &req, sizeof(req), inet6_tcp_receive_one);
	if (tmp)
		err = tmp;

	/* Collect IPv6 UDP sockets */
	req.r.i.sdiag_family	= AF_INET6;
	req.r.i.sdiag_protocol	= IPPROTO_UDP;
	req.r.i.idiag_ext	= 0;
	req.r.i.idiag_states	= -1; /* All */
	tmp = collect_sockets_nl(nl, &req, sizeof(req), inet6_udp_receive_one);
	if (tmp)
		err = tmp;

	/* Collect IPv6 UDP-lite sockets */
	req.r.i.sdiag_family	= AF_INET6;
	req.r.i.sdiag_protocol	= IPPROTO_UDPLITE;
	req.r.i.idiag_ext	= 0;
	req.r.i.idiag_states	= -1; /* All */
	tmp = collect_sockets_nl(nl, &req, sizeof(req), inet6_udplite_receive_one);
	if (tmp)
		err = tmp;
out:
	close(nl);
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

