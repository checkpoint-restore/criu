#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/tcp.h>

#include "libnetlink.h"
#include "sockets.h"
#include "unix_diag.h"
#include "inet_diag.h"
#include "packet_diag.h"
#include "files.h"
#include "util-net.h"
#include "sk-packet.h"
#include "namespaces.h"
#include "crtools.h"

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

struct socket_desc *lookup_socket(int ino, int family)
{
	struct socket_desc *sd;

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

int restore_socket_opts(int sk, SkOptsEntry *soe)
{
	int ret = 0;
	struct timeval tv;

	ret |= restore_opt(sk, SOL_SOCKET, SO_SNDBUFFORCE, &soe->so_sndbuf);
	ret |= restore_opt(sk, SOL_SOCKET, SO_RCVBUFFORCE, &soe->so_rcvbuf);

	tv.tv_sec = soe->so_snd_tmo_sec;
	tv.tv_usec = soe->so_snd_tmo_usec;
	ret |= restore_opt(sk, SOL_SOCKET, SO_SNDTIMEO, &tv);

	tv.tv_sec = soe->so_rcv_tmo_sec;
	tv.tv_usec = soe->so_rcv_tmo_usec;
	ret |= restore_opt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv);

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

	ret |= dump_opt(sk, SOL_SOCKET, SO_SNDTIMEO, &tv);
	soe->so_snd_tmo_sec = tv.tv_sec;
	soe->so_snd_tmo_usec = tv.tv_usec;

	ret |= dump_opt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv);
	soe->so_rcv_tmo_sec = tv.tv_sec;
	soe->so_rcv_tmo_usec = tv.tv_usec;

	ret |= dump_opt(sk, SOL_SOCKET, SO_REUSEADDR, &val);
	soe->reuseaddr = val ? true : false;
	soe->has_reuseaddr = true;

	return ret;
}

int dump_socket(struct fd_parms *p, int lfd, const struct cr_fdset *cr_fdset)
{
	int family;

	if (dump_opt(lfd, SOL_SOCKET, SO_DOMAIN, &family))
		return -1;

	switch (family) {
	case AF_UNIX:
		return dump_one_unix(p, lfd, cr_fdset);
	case AF_INET:
		return dump_one_inet(p, lfd, cr_fdset);
	case AF_INET6:
		return dump_one_inet6(p, lfd, cr_fdset);
	case AF_PACKET:
		return dump_one_packet_sk(p, lfd, cr_fdset);
	default:
		pr_err("BUG! Unknown socket collected\n");
		break;
	}

	return -1;
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

	return inet_collect_one(h, i->sdiag_family, type, i->sdiag_protocol);
}

int collect_sockets(int pid)
{
	int err = 0, tmp;
	int rst = -1;
	int nl;
	struct {
		struct nlmsghdr hdr;
		union {
			struct unix_diag_req	u;
			struct inet_diag_req_v2	i;
			struct packet_diag_req	p;
		} r;
	} req;

	if (opts.namespaces_flags & CLONE_NEWNET) {
		pr_info("Switching to %d's net for collecting sockets\n", pid);

		if (switch_ns(pid, CLONE_NEWNET, "net", &rst))
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
	tmp = do_rtnl_req(nl, &req, sizeof(req), unix_receive_one, NULL);
	if (tmp)
		err = tmp;

	/* Collect IPv4 TCP sockets */
	req.r.i.sdiag_family	= AF_INET;
	req.r.i.sdiag_protocol	= IPPROTO_TCP;
	req.r.i.idiag_ext	= 0;
	/* Only listening and established sockets supported yet */
	req.r.i.idiag_states	= (1 << TCP_LISTEN) | (1 << TCP_ESTABLISHED);
	tmp = do_rtnl_req(nl, &req, sizeof(req), inet_receive_one, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv4 UDP sockets */
	req.r.i.sdiag_family	= AF_INET;
	req.r.i.sdiag_protocol	= IPPROTO_UDP;
	req.r.i.idiag_ext	= 0;
	req.r.i.idiag_states	= -1; /* All */
	tmp = do_rtnl_req(nl, &req, sizeof(req), inet_receive_one, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv4 UDP-lite sockets */
	req.r.i.sdiag_family	= AF_INET;
	req.r.i.sdiag_protocol	= IPPROTO_UDPLITE;
	req.r.i.idiag_ext	= 0;
	req.r.i.idiag_states	= -1; /* All */
	tmp = do_rtnl_req(nl, &req, sizeof(req), inet_receive_one, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv6 TCP sockets */
	req.r.i.sdiag_family	= AF_INET6;
	req.r.i.sdiag_protocol	= IPPROTO_TCP;
	req.r.i.idiag_ext	= 0;
	/* Only listening sockets supported yet */
	req.r.i.idiag_states	= 1 << TCP_LISTEN;
	tmp = do_rtnl_req(nl, &req, sizeof(req), inet_receive_one, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv6 UDP sockets */
	req.r.i.sdiag_family	= AF_INET6;
	req.r.i.sdiag_protocol	= IPPROTO_UDP;
	req.r.i.idiag_ext	= 0;
	req.r.i.idiag_states	= -1; /* All */
	tmp = do_rtnl_req(nl, &req, sizeof(req), inet_receive_one, &req.r.i);
	if (tmp)
		err = tmp;

	/* Collect IPv6 UDP-lite sockets */
	req.r.i.sdiag_family	= AF_INET6;
	req.r.i.sdiag_protocol	= IPPROTO_UDPLITE;
	req.r.i.idiag_ext	= 0;
	req.r.i.idiag_states	= -1; /* All */
	tmp = do_rtnl_req(nl, &req, sizeof(req), inet_receive_one, &req.r.i);
	if (tmp)
		err = tmp;

	req.r.p.sdiag_family	= AF_PACKET;
	req.r.p.sdiag_protocol	= 0;
	req.r.p.pdiag_show	= PACKET_SHOW_INFO | PACKET_SHOW_MCLIST |
					PACKET_SHOW_FANOUT | PACKET_SHOW_RING_CFG;
	tmp = do_rtnl_req(nl, &req, sizeof(req), packet_receive_one, NULL);
	if (tmp)
		err = tmp;

	close(nl);
out:
	if (rst > 0 && restore_ns(rst, CLONE_NEWNET) < 0)
		err = -1;
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

void show_socket_opts(SkOptsEntry *soe)
{
	pr_msg("\t");

	pr_msg("sndbuf: %u  ", soe->so_sndbuf);
	pr_msg("rcvbuf: %u  ", soe->so_rcvbuf);
	pr_msg("sndtmo: %lu.%lu  ", soe->so_snd_tmo_sec, soe->so_snd_tmo_usec);
	pr_msg("rcvtmo: %lu.%lu  ", soe->so_rcv_tmo_sec, soe->so_rcv_tmo_usec);

	pr_msg("\n");
}
