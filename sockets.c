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
#include <arpa/inet.h>
#include <sys/sendfile.h>

#include "types.h"
#include "libnetlink.h"
#include "sockets.h"
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

struct socket_desc {
	unsigned int		family;
	unsigned int		ino;
	struct socket_desc	*next;
	int			already_dumped;
};

struct unix_sk_desc {
	struct socket_desc	sd;
	unsigned int		type;
	unsigned int		state;
	unsigned int		peer_ino;
	unsigned int		rqlen;
	unsigned int		wqlen;
	unsigned int		namelen;
	char			*name;
	unsigned int		nr_icons;
	unsigned int		*icons;
};

struct unix_sk_listen_icon {
	unsigned int			peer_ino;
	struct unix_sk_desc		*sk_desc;
	struct unix_sk_listen_icon	*next;
};

#define INET_ADDR_LEN		40

struct inet_sk_desc {
	struct socket_desc	sd;
	unsigned int		type;
	unsigned int		proto;
	unsigned int		src_port;
	unsigned int		dst_port;
	unsigned int		state;
	unsigned int		rqlen;
	unsigned int		wqlen;
	unsigned int		src_addr[4];
	unsigned int		dst_addr[4];
};

static int dump_socket_queue(int sock_fd, int sock_id)
{
	struct sk_packet_entry *pe;
	unsigned long size;
	socklen_t tmp;
	int ret, orig_peek_off;

	/*
	 * Save original peek offset. 
	 */
	tmp = sizeof(orig_peek_off);
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed\n");
		return ret;
	}
	/*
	 * Discover max DGRAM size
	 */
	tmp = sizeof(size);
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &size, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed\n");
		return ret;
	}

	/* Note: 32 bytes will be used by kernel for protocol header. */
	size -= 32;
	/*
	 * Try to alloc buffer for max supported DGRAM + our header.
	 * Note: STREAM queue will be written by chunks of this size.
	 */
	pe = xmalloc(size + sizeof(struct sk_packet_entry));
	if (!pe)
		return -ENOMEM;

	/*
	 * Enable peek offset incrementation.
	 */
	ret = setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &ret, sizeof(int));
	if (ret < 0) {
		pr_perror("setsockopt fail\n");
		goto err_brk;
	}

	pe->id_for = sock_id;

	while (1) {
		struct iovec iov = {
			.iov_base	= pe->data,
			.iov_len	= size,
		};
		struct msghdr msg = {
			.msg_iov	= &iov,
			.msg_iovlen	= 1,
		};

		ret = pe->length = recvmsg(sock_fd, &msg, MSG_DONTWAIT | MSG_PEEK);
		if (ret < 0) {
			if (ret == -EAGAIN)
				break; /* we're done */
			pr_perror("sys_recvmsg fail: error\n");
			goto err_set_sock;
		}
		if (msg.msg_flags & MSG_TRUNC) {
			/*
			 * DGRAM thuncated. This should not happen. But we have
			 * to check...
			 */
			pr_err("sys_recvmsg failed: truncated\n");
			ret = -E2BIG;
			goto err_set_sock;
		}
		ret = write_img_buf(fdset_fd(glob_fdset, CR_FD_SK_QUEUES),
				pe, sizeof(pe) + pe->length);
		if (ret < 0) {
			ret = -EIO;
			goto err_set_sock;
		}
	}
	ret = 0;

err_set_sock:
	/*
	 * Restore original peek offset. 
	 */
	ret = setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, sizeof(int));
	if (ret < 0)
		pr_perror("setsockopt failed on restore\n");
err_brk:
	xfree(pe);
	return ret;
}

#define SK_HASH_SIZE		32
#define SK_HASH_LINK(head, key, elem)					\
	do {								\
		(elem)->next = (head)[(key) % SK_HASH_SIZE];		\
		(head)[(key) % SK_HASH_SIZE] = (elem);			\
	} while (0)

#define __gen_static_lookup_func(ret, name, head, _member, _type, _name)\
	static ret *name(_type _name) {					\
		ret *d;							\
		for (d = head[_name % SK_HASH_SIZE]; d; d = d->next) {	\
			if (d->_member == _name)			\
				break;					\
		}							\
		return d;						\
	}

static struct socket_desc *sockets[SK_HASH_SIZE];
__gen_static_lookup_func(struct socket_desc, lookup_socket, sockets,
			ino, int, ino);

static struct unix_sk_listen_icon *unix_listen_icons[SK_HASH_SIZE];
__gen_static_lookup_func(struct unix_sk_listen_icon,
			 lookup_unix_listen_icons,
			 unix_listen_icons,
			 peer_ino, unsigned int, ino);

static int sk_collect_one(int ino, int family, struct socket_desc *d)
{
	d->ino		= ino;
	d->family	= family;

	SK_HASH_LINK(sockets, ino, d);

	return 0;
}

static void show_one_inet(const char *act, const struct inet_sk_desc *sk)
{
	char src_addr[INET_ADDR_LEN] = "<unknown>";

	if (inet_ntop(AF_INET, (void *)sk->src_addr, src_addr,
		      INET_ADDR_LEN) == NULL) {
		pr_perror("Failed to translate address");
	}

	pr_debug("\t%s: ino 0x%x family %d type %d port %d "
		"state %d src_addr %s\n",
		act, sk->sd.ino, sk->sd.family, sk->type, sk->src_port,
		sk->state, src_addr);
}

static void show_one_inet_img(const char *act, const struct inet_sk_entry *e)
{
	char src_addr[INET_ADDR_LEN] = "<unknown>";

	if (inet_ntop(AF_INET, (void *)e->src_addr, src_addr,
		      INET_ADDR_LEN) == NULL) {
		pr_perror("Failed to translate address");
	}

	pr_debug("\t%s: family %d type %d proto %d port %d "
		"state %d src_addr %s\n",
		act, e->family, e->type, e->proto, e->src_port,
		e->state, src_addr);
}

static void show_one_unix(char *act, const struct unix_sk_desc *sk)
{
	pr_debug("\t%s: ino 0x%x type %d state %d name %s\n",
		act, sk->sd.ino, sk->type, sk->state, sk->name);

	if (sk->nr_icons) {
		int i;

		for (i = 0; i < sk->nr_icons; i++)
			pr_debug("\t\ticon: %4d\n", sk->icons[i]);
	}
}

static void show_one_unix_img(const char *act, const struct unix_sk_entry *e)
{
	pr_info("\t%s: id %u type %d state %d name %d bytes\n",
		act, e->id, e->type, e->state, e->namelen);
}

static int can_dump_inet_sk(const struct inet_sk_desc *sk)
{
	if (sk->sd.family != AF_INET) {
		pr_err("Only IPv4 sockets for now\n");
		return 0;
	}

	if (sk->type == SOCK_DGRAM)
		return 1;

	if (sk->type != SOCK_STREAM) {
		pr_err("Only stream and dgram inet sockets for now\n");
		return 0;
	}

	switch (sk->state) {
	case TCP_LISTEN:
		if (sk->rqlen != 0) {
			/*
			 * Currently the ICONS nla reports the conn
			 * requests for listen sockets. Need to pick
			 * those up and fix the connect job respectively
			 */
			pr_err("In-flight connection (l)\n");
			return 0;
		}
		break;
	default:
		pr_err("Unknown state %d\n", sk->state);
		return 0;
	}

	return 1;
}

static int dump_one_inet(struct socket_desc *_sk, struct fd_parms *p,
			 const struct cr_fdset *cr_fdset)
{
	struct inet_sk_desc *sk = (struct inet_sk_desc *)_sk;
	struct inet_sk_entry ie;
	struct fdinfo_entry fe;

	if (!can_dump_inet_sk(sk))
		goto err;

	fe.fd = p->fd;
	fe.type = FDINFO_INETSK;
	fe.id = sk->sd.ino;
	fe.flags = p->fd_flags;

	if (write_img(fdset_fd(cr_fdset, CR_FD_FDINFO), &fe))
		goto err;

	if (sk->sd.already_dumped)
		return 0;

	memset(&ie, 0, sizeof(ie));

	ie.id		= sk->sd.ino;
	ie.family	= sk->sd.family;
	ie.type		= sk->type;
	ie.proto	= sk->proto;
	ie.state	= sk->state;
	ie.src_port	= sk->src_port;
	ie.dst_port	= sk->dst_port;
	ie.backlog	= sk->wqlen;
	ie.flags	= p->flags;
	ie.fown		= p->fown;
	memcpy(ie.src_addr, sk->src_addr, sizeof(u32) * 4);
	memcpy(ie.dst_addr, sk->dst_addr, sizeof(u32) * 4);

	if (write_img(fdset_fd(glob_fdset, CR_FD_INETSK), &ie))
		goto err;

	pr_info("Dumping inet socket at %d\n", p->fd);
	show_one_inet("Dumping", sk);
	show_one_inet_img("Dumped", &ie);
	sk->sd.already_dumped = 1;
	return 0;

err:
	return -1;
}

static int can_dump_unix_sk(const struct unix_sk_desc *sk)
{
	if (sk->type != SOCK_STREAM &&
	    sk->type != SOCK_DGRAM) {
		pr_err("Only stream/dgram sockets for now\n");
		return 0;
	}

	switch (sk->state) {
	case TCP_LISTEN:
		break;
	case TCP_ESTABLISHED:
		break;
	case TCP_CLOSE:
		if (sk->type != SOCK_DGRAM)
			return 0;
		break;
	default:
		pr_err("Unknown state %d\n", sk->state);
		return 0;
	}

	return 1;
}

static int dump_one_unix(const struct socket_desc *_sk, struct fd_parms *p,
		int lfd, const struct cr_fdset *cr_fdset)
{
	struct unix_sk_desc *sk = (struct unix_sk_desc *)_sk;
	struct fdinfo_entry fe;
	struct unix_sk_entry ue;

	if (!can_dump_unix_sk(sk))
		goto err;

	fe.fd = p->fd;
	fe.type = FDINFO_UNIXSK;
	fe.id = sk->sd.ino;
	fe.flags = p->fd_flags;

	if (write_img(fdset_fd(cr_fdset, CR_FD_FDINFO), &fe))
		goto err;

	if (sk->sd.already_dumped)
		return 0;

	ue.id		= sk->sd.ino;
	ue.type		= sk->type;
	ue.state	= sk->state;
	ue.namelen	= sk->namelen;
	ue.flags	= p->flags;
	ue.backlog	= sk->wqlen;
	ue.peer		= sk->peer_ino;
	ue.fown		= p->fown;

	if (ue.peer) {
		struct unix_sk_desc *peer;

		peer = (struct unix_sk_desc *)lookup_socket(ue.peer);
		if (!peer) {
			pr_err("Unix socket 0x%x without peer 0x%x\n",
					ue.id, ue.peer);
			goto err;
		}

		/*
		 * Peer should have us as peer or have a name by which
		 * we can access one.
		 */
		if (!peer->name && (peer->peer_ino != ue.id)) {
			pr_err("Unix socket 0x%x with unreachable peer 0x%x (0x%x/%s)\n",
					ue.id, ue.peer, peer->peer_ino, peer->name);
			goto err;
		}
	} else if (ue.state == TCP_ESTABLISHED) {
		const struct unix_sk_listen_icon *e;

		/*
		 * If this is in-flight connection we need to figure
		 * out where to connect it on restore. Thus, tune up peer
		 * id by searching an existing listening socket.
		 *
		 * Note the socket name will be found at restore stage,
		 * not now, just to reduce size of dump files.
		 */

		e = lookup_unix_listen_icons(ue.id);
		if (!e) {
			pr_err("Dangling in-flight connection %d\n", ue.id);
			goto err;
		}

		/* e->sk_desc is _never_ NULL */
		if (e->sk_desc->state != TCP_LISTEN) {
			pr_err("In-flight connection on "
				"non-listening socket %d\n", ue.id);
			goto err;
		}

		ue.peer = e->sk_desc->sd.ino;

		pr_debug("\t\tFixed inflight socket 0x%x peer 0x%x)\n",
				ue.id, ue.peer);
	}

	if (write_img(fdset_fd(glob_fdset, CR_FD_UNIXSK), &ue))
		goto err;
	if (write_img_buf(fdset_fd(glob_fdset, CR_FD_UNIXSK), sk->name, ue.namelen))
		goto err;

	if (sk->rqlen != 0 && !(sk->type == SOCK_STREAM &&
				sk->state == TCP_LISTEN))
		if (dump_socket_queue(lfd, ue.id))
			goto err;

	pr_info("Dumping unix socket at %d\n", p->fd);
	show_one_unix("Dumping", sk);
	show_one_unix_img("Dumped", &ue);

	sk->sd.already_dumped = 1;
	return 0;

err:
	return -1;
}

int dump_socket(struct fd_parms *p, int lfd, const struct cr_fdset *cr_fdset)
{
	struct socket_desc *sk;

	sk = lookup_socket(p->stat.st_ino);
	if (!sk) {
		pr_err("Uncollected socket %ld\n", p->stat.st_ino);
		return -1;
	}

	switch (sk->family) {
	case AF_UNIX:
		return dump_one_unix(sk, p, lfd, cr_fdset);
	case AF_INET:
		return dump_one_inet(sk, p, cr_fdset);
	default:
		pr_err("BUG! Unknown socket collected\n");
		break;
	}

	return -1;
}

static int inet_collect_one(struct nlmsghdr *h, int type, int proto)
{
	struct inet_sk_desc *d;
	struct inet_diag_msg *m = NLMSG_DATA(h);
	struct rtattr *tb[INET_DIAG_MAX+1];

	parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr *)(m + 1),
		     h->nlmsg_len - NLMSG_LENGTH(sizeof(*m)));

	d = xzalloc(sizeof(*d));
	if (!d)
		return -1;

	d->type = type;
	d->proto = proto;
	d->src_port = ntohs(m->id.idiag_sport);
	d->dst_port = ntohs(m->id.idiag_dport);
	d->state = m->idiag_state;
	d->rqlen = m->idiag_rqueue;
	d->wqlen = m->idiag_wqueue;
	memcpy(d->src_addr, m->id.idiag_src, sizeof(u32) * 4);
	memcpy(d->dst_addr, m->id.idiag_dst, sizeof(u32) * 4);

	return sk_collect_one(m->idiag_inode, AF_INET, &d->sd);
}

static int inet_tcp_receive_one(struct nlmsghdr *h)
{
	return inet_collect_one(h, SOCK_STREAM, IPPROTO_TCP);
}

static int inet_udp_receive_one(struct nlmsghdr *h)
{
	return inet_collect_one(h, SOCK_DGRAM, IPPROTO_UDP);
}

static int inet_udplite_receive_one(struct nlmsghdr *h)
{
	return inet_collect_one(h, SOCK_DGRAM, IPPROTO_UDPLITE);
}

static int unix_collect_one(const struct unix_diag_msg *m,
		struct rtattr **tb)
{
	struct unix_sk_desc *d, **h;

	d = xzalloc(sizeof(*d));
	if (!d)
		return -1;

	d->type	= m->udiag_type;
	d->state= m->udiag_state;

	if (tb[UNIX_DIAG_PEER])
		d->peer_ino = *(int *)RTA_DATA(tb[UNIX_DIAG_PEER]);

	if (tb[UNIX_DIAG_NAME]) {
		int len		= RTA_PAYLOAD(tb[UNIX_DIAG_NAME]);
		char *name	= xmalloc(len + 1);

		if (!name)
			goto err;

		memcpy(name, RTA_DATA(tb[UNIX_DIAG_NAME]), len);
		name[len] = '\0';

		if (name[0] != '\0') {
			struct unix_diag_vfs *uv;
			struct stat st;

			if (name[0] != '/') {
				pr_warn("Relative bind path '%s' "
					"unsupported\n", name);
				xfree(name);
				xfree(d);
				return 0;
			}

			if (!tb[UNIX_DIAG_VFS]) {
				pr_err("Bound socket w/o inode %d\n",
						m->udiag_ino);
				goto err;
			}

			uv = RTA_DATA(tb[UNIX_DIAG_VFS]);
			if (stat(name, &st)) {
				pr_perror("Can't stat socket %d(%s)",
						m->udiag_ino, name);
				goto err;
			}

			if ((st.st_ino != uv->udiag_vfs_ino) ||
			    (st.st_dev != kdev_to_odev(uv->udiag_vfs_dev))) {
				pr_info("unix: Dropping path for "
						"unlinked bound "
						"sk 0x%x.0x%x real 0x%x.0x%x\n",
						(int)st.st_dev,
						(int)st.st_ino,
						(int)uv->udiag_vfs_dev,
						(int)uv->udiag_vfs_ino);
				/*
				 * When a socket is bound to unlinked file, we
				 * just drop his name, since noone will access
				 * it via one.
				 */
				xfree(name);
				len = 0;
				name = NULL;
			}
		}

		d->namelen = len;
		d->name = name;
	}

	if (tb[UNIX_DIAG_ICONS]) {
		int len = RTA_PAYLOAD(tb[UNIX_DIAG_ICONS]);
		int i;

		d->icons = xmalloc(len);
		if (!d->icons)
			goto err;

		memcpy(d->icons, RTA_DATA(tb[UNIX_DIAG_ICONS]), len);
		d->nr_icons = len / sizeof(u32);

		/*
		 * Remember these sockets, we will need them
		 * to fix up in-flight sockets peers.
		 */
		for (i = 0; i < d->nr_icons; i++) {
			struct unix_sk_listen_icon *e;
			int n;

			e = xzalloc(sizeof(*e));
			if (!e)
				goto err;

			SK_HASH_LINK(unix_listen_icons, d->icons[i], e);

			pr_debug("\t\tCollected icon %d\n", d->icons[i]);

			e->peer_ino	= d->icons[i];
			e->sk_desc	= d;
		}


	}

	if (tb[UNIX_DIAG_RQLEN]) {
		struct unix_diag_rqlen *rq;

		rq = (struct unix_diag_rqlen *)RTA_DATA(tb[UNIX_DIAG_RQLEN]);
		d->rqlen = rq->udiag_rqueue;
		d->wqlen = rq->udiag_wqueue;
	}

	sk_collect_one(m->udiag_ino, AF_UNIX, &d->sd);
	show_one_unix("Collected", d);

	return 0;

err:
	xfree(d->icons);
	xfree(d->name);
	xfree(d);
	return -1;
}

static int unix_receive_one(struct nlmsghdr *h)
{
	struct unix_diag_msg *m = NLMSG_DATA(h);
	struct rtattr *tb[UNIX_DIAG_MAX+1];

	parse_rtattr(tb, UNIX_DIAG_MAX, (struct rtattr *)(m + 1),
		     h->nlmsg_len - NLMSG_LENGTH(sizeof(*m)));

	return unix_collect_one(m, tb);
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

out:
	close(nl);
	return err;
}

struct unix_sk_info {
	struct unix_sk_entry ue;
	struct list_head list;
	char *name;
	unsigned flags;
	struct unix_sk_info *peer;
	struct file_desc d;
};

#define USK_PAIR_MASTER		0x1
#define USK_PAIR_SLAVE		0x2

static LIST_HEAD(unix_sockets);

static struct unix_sk_info *find_unix_sk(int id)
{
	struct file_desc *d;

	d = find_file_desc_raw(FDINFO_UNIXSK, id);
	if (d)
		return container_of(d, struct unix_sk_info, d);
	return NULL;
}

struct sk_packet {
	struct list_head list;
	struct sk_packet_entry entry;
	off_t img_off;
};

static LIST_HEAD(packets_list);

static int read_sockets_queues(void)
{
	struct sk_packet *pkt;
	int ret, fd;

	pr_info("Trying to read socket queues image\n");

	fd = open_image_ro(CR_FD_SK_QUEUES);
	if (fd < 0)
		return -1;

	while (1) {
		struct sk_packet_entry tmp;

		pkt = xmalloc(sizeof(*pkt));
		if (!pkt) {
			pr_err("Failed to allocate packet header\n");
			return -ENOMEM;
		}
		ret = read_img_eof(fd, &pkt->entry);
		if (ret <= 0)
			break;

		pkt->img_off = lseek(fd, 0, SEEK_CUR);
		/*
		 * NOTE: packet must be added to the tail. Otherwise sequence
		 * will be broken.
		 */
		list_add_tail(&pkt->list, &packets_list);
		lseek(fd, pkt->entry.length, SEEK_CUR);
	}
	close(fd);
	xfree(pkt);

	return ret;
}

static int restore_socket_queue(int fd, unsigned int peer_id)
{
	struct sk_packet *pkt, *tmp;
	int ret, img_fd;

	pr_info("Trying to restore recv queue for %u\n", peer_id);

	img_fd = open_image_ro(CR_FD_SK_QUEUES);
	if (img_fd < 0)
		return -1;

	list_for_each_entry_safe(pkt, tmp, &packets_list, list) {
		struct sk_packet_entry *entry = &pkt->entry;

		if (entry->id_for != peer_id)
			continue;

		pr_info("\tRestoring %d-bytes skb for %u\n",
				entry->length, peer_id);

		ret = sendfile(fd, img_fd, &pkt->img_off, entry->length);
		if (ret < 0) {
			pr_perror("Failed to sendfile packet");
			return -1;
		}
		if (ret != entry->length) {
			pr_err("Restored skb trimmed to %d/%d\n",
					ret, entry->length);
			return -1;
		}
		list_del(&pkt->list);
		xfree(pkt);
	}

	close(img_fd);
	return 0;
}

struct inet_sk_info {
	struct inet_sk_entry ie;
	struct file_desc d;
};

static int open_inet_sk(struct file_desc *d);

static struct file_desc_ops inet_desc_ops = {
	.open = open_inet_sk,
};

int collect_inet_sockets(void)
{
	struct inet_sk_info *ii = NULL;
	int fd, ret = -1;

	fd = open_image_ro(CR_FD_INETSK);
	if (fd < 0)
		return -1;

	while (1) {
		ii = xmalloc(sizeof(*ii));
		ret = -1;
		if (!ii)
			break;

		ret = read_img_eof(fd, &ii->ie);
		if (ret <= 0)
			break;

		file_desc_add(&ii->d, FDINFO_INETSK, ii->ie.id,
				&inet_desc_ops);
	}

	if (ii)
		xfree(ii);

	close(fd);
	return 0;
}

static int open_inet_sk(struct file_desc *d)
{
	int sk;
	struct sockaddr_in addr;
	struct inet_sk_info *ii;

	ii = container_of(d, struct inet_sk_info, d);

	show_one_inet_img("Restore", &ii->ie);

	if (ii->ie.family != AF_INET) {
		pr_err("Unsupported socket family: %d\n", ii->ie.family);
		return -1;
	}

	if ((ii->ie.type != SOCK_STREAM) && (ii->ie.type != SOCK_DGRAM)) {
		pr_err("Unsupported socket type: %d\n", ii->ie.type);
		return -1;
	}

	sk = socket(ii->ie.family, ii->ie.type, ii->ie.proto);
	if (sk < 0) {
		pr_perror("Can't create unix socket");
		return -1;
	}

	if (restore_fown(sk, &ii->ie.fown))
		goto err;

	/*
	 * Listen sockets are easiest ones -- simply
	 * bind() and listen(), and that's all.
	 */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = ii->ie.family;
	addr.sin_port = htons(ii->ie.src_port);
	memcpy(&addr.sin_addr.s_addr, ii->ie.src_addr, sizeof(unsigned int) * 4);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		pr_perror("Can't bind to a socket");
		goto err;
	}

	if (ii->ie.state == TCP_LISTEN) {
		if (ii->ie.proto != IPPROTO_TCP) {
			pr_err("Wrong socket in listen state %d\n", ii->ie.proto);
			goto err;
		}

		if (listen(sk, ii->ie.backlog) == -1) {
			pr_perror("Can't listen on a socket");
			goto err;
		}
	}

	if (ii->ie.state == TCP_ESTABLISHED) {
		if (ii->ie.proto == IPPROTO_TCP) {
			pr_err("Connected TCP socket in image\n");
			goto err;
		}

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = ii->ie.family;
		addr.sin_port = htons(ii->ie.dst_port);
		memcpy(&addr.sin_addr.s_addr, ii->ie.dst_addr, sizeof(ii->ie.dst_addr));

		if (connect(sk, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
			pr_perror("Can't connect UDP socket back");
			goto err;
		}
	}

	if (set_fd_flags(sk, ii->ie.flags))
		return -1;

	return sk;

err:
	close(sk);
	return -1;
}

static inline char *unknown(u32 val)
{
	static char unk[12];
	snprintf(unk, sizeof(unk), "x%d", val);
	return unk;
}

static inline char *skfamily2s(u32 f)
{
	if (f == AF_INET)
		return " inet";
	else
		return unknown(f);
}

static inline char *sktype2s(u32 t)
{
	if (t == SOCK_STREAM)
		return "stream";
	else if (t == SOCK_DGRAM)
		return " dgram";
	else
		return unknown(t);
}

static inline char *skproto2s(u32 p)
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

static inline char *skstate2s(u32 state)
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

void show_inetsk(int fd, struct cr_options *o)
{
	struct inet_sk_entry ie;
	int ret = 0;

	pr_img_head(CR_FD_INETSK);

	while (1) {
		char src_addr[INET_ADDR_LEN] = "<unknown>";
		char dst_addr[INET_ADDR_LEN] = "<unknown>";

		ret = read_img_eof(fd, &ie);
		if (ret <= 0)
			goto out;

		if (inet_ntop(AF_INET, (void *)ie.src_addr, src_addr,
			      INET_ADDR_LEN) == NULL) {
			pr_perror("Failed to translate src address");
		}

		if (ie.state == TCP_ESTABLISHED) {
			if (inet_ntop(AF_INET, (void *)ie.dst_addr, dst_addr,
				      INET_ADDR_LEN) == NULL) {
				pr_perror("Failed to translate dst address");
			}
		}

		pr_msg("id 0x%x family %s type %s proto %s state %s %s:%d <-> %s:%d flags 0x%2x\n",
			ie.id, skfamily2s(ie.family), sktype2s(ie.type), skproto2s(ie.proto),
			skstate2s(ie.state), src_addr, ie.src_port, dst_addr, ie.dst_port, ie.flags);
		pr_msg("\t"), show_fown_cont(&ie.fown), pr_msg("\n");
	}

out:
	if (ret)
		pr_info("\n");
	pr_img_tail(CR_FD_INETSK);
}

void show_unixsk(int fd, struct cr_options *o)
{
	struct unix_sk_entry ue;
	int ret = 0;

	pr_img_head(CR_FD_UNIXSK);

	while (1) {
		ret = read_img_eof(fd, &ue);
		if (ret <= 0)
			goto out;

		pr_msg("id 0x%8x type %s state %s namelen %4d backlog %4d peer 0x%8x flags 0x%2x",
			ue.id, sktype2s(ue.type), skstate2s(ue.state),
			ue.namelen, ue.backlog, ue.peer, ue.flags);

		if (ue.namelen) {
			BUG_ON(ue.namelen > sizeof(buf));
			ret = read_img_buf(fd, buf, ue.namelen);
			if (ret < 0) {
				pr_info("\n");
				goto out;
			}
			if (!buf[0])
				buf[0] = '@';
			pr_msg(" --> %s\n", buf);
		} else
			pr_msg("\n");
		pr_msg("\t"), show_fown_cont(&ue.fown), pr_msg("\n");
	}
out:
	pr_img_tail(CR_FD_UNIXSK);
}

void show_sk_queues(int fd, struct cr_options *o)
{
	struct sk_packet_entry pe;
	int ret;

	pr_img_head(CR_FD_SK_QUEUES);
	while (1) {
		ret = read_img_eof(fd, &pe);
		if (ret <= 0)
			break;

		pr_info("pkt for %u length %u bytes\n",
				pe.id_for, pe.length);

		ret = read_img_buf(fd, (unsigned char *)buf, pe.length);
		if (ret < 0)
			break;

		print_data(0, (unsigned char *)buf, pe.length);
	}
	pr_img_tail(CR_FD_SK_QUEUES);
}

struct unix_conn_job {
	struct unix_sk_info	*sk;
	struct unix_conn_job	*next;
};

static struct unix_conn_job *conn_jobs;

static int schedule_conn_job(struct unix_sk_info *ui)
{
	struct unix_conn_job *cj;

	cj = xmalloc(sizeof(*cj));
	if (!cj)
		return -1;

	cj->sk = ui;
	cj->next = conn_jobs;
	conn_jobs = cj;

	return 0;
}

int run_unix_connections(void)
{
	struct unix_conn_job *cj;

	pr_info("Running delayed unix connections\n");

	cj = conn_jobs;
	while (cj) {
		int attempts = 8;
		struct unix_sk_info *ui = cj->sk;
		struct unix_sk_info *peer = ui->peer;
		struct fdinfo_list_entry *fle;
		struct sockaddr_un addr;

		pr_info("\tConnect 0x%x to 0x%x\n", ui->ue.id, peer->ue.id);

		fle = file_master(&ui->d);

		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		memcpy(&addr.sun_path, peer->name, peer->ue.namelen);
try_again:
		if (connect(fle->fd, (struct sockaddr *)&addr,
					sizeof(addr.sun_family) +
					peer->ue.namelen) < 0) {
			if (attempts) {
				usleep(1000);
				attempts--;
				goto try_again; /* FIXME use futex waiters */
			}

			pr_perror("Can't connect 0x%x socket", ui->ue.id);
			return -1;
		}

		if (restore_socket_queue(fle->fd, peer->ue.id))
			return -1;

		if (set_fd_flags(fle->fd, ui->ue.flags))
			return -1;

		cj = cj->next;
	}

	return 0;
}

static int bind_unix_sk(int sk, struct unix_sk_info *ui)
{
	struct sockaddr_un addr;

	if ((ui->ue.type == SOCK_STREAM) && (ui->ue.state != TCP_LISTEN))
		/*
		 * FIXME this can be done, but for doing this properly we
		 * need to bind socket to its name, then rename one to
		 * some temporary unique one and after all the sockets are
		 * restored we should walk those temp names and rename
		 * some of them back to real ones.
		 */
		goto done;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(&addr.sun_path, ui->name, ui->ue.namelen);

	if (bind(sk, (struct sockaddr *)&addr,
				sizeof(addr.sun_family) + ui->ue.namelen)) {
		pr_perror("Can't bind socket");
		return -1;
	}
done:
	return 0;
}

static int unixsk_should_open_transport(struct fdinfo_entry *fe,
				struct file_desc *d)
{
	struct unix_sk_info *ui;

	ui = container_of(d, struct unix_sk_info, d);
	return ui->flags & USK_PAIR_SLAVE;
}

static int open_unixsk_pair_master(struct unix_sk_info *ui)
{
	int sk[2], tsk;
	struct unix_sk_info *peer = ui->peer;
	struct fdinfo_list_entry *fle;

	pr_info("Opening pair master (id 0x%x peer 0x%x)\n",
			ui->ue.id, ui->ue.peer);

	if (socketpair(PF_UNIX, ui->ue.type, 0, sk) < 0) {
		pr_perror("Can't make socketpair");
		return -1;
	}

	if (restore_socket_queue(sk[0], peer->ue.id))
		return -1;
	if (restore_socket_queue(sk[1], ui->ue.id))
		return -1;

	if (set_fd_flags(sk[0], ui->ue.flags))
		return -1;
	if (set_fd_flags(sk[1], peer->ue.flags))
		return -1;

	if (restore_fown(sk[0], &ui->ue.fown))
		return -1;
	if (restore_fown(sk[1], &peer->ue.fown))
		return -1;

	if (bind_unix_sk(sk[0], ui))
		return -1;

	tsk = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (tsk < 0) {
		pr_perror("Can't make transport socket");
		return -1;
	}

	fle = file_master(&peer->d);
	if (send_fd_to_peer(sk[1], fle, tsk)) {
		pr_err("Can't send pair slave\n");
		return -1;
	}

	close(tsk);
	close(sk[1]);

	return sk[0];
}

static int open_unixsk_pair_slave(struct unix_sk_info *ui)
{
	struct fdinfo_list_entry *fle;
	int sk;

	fle = file_master(&ui->d);

	pr_info("Opening pair slave (id 0x%x peer 0x%x) on %d\n",
			ui->ue.id, ui->ue.peer, fle->fd);

	sk = recv_fd(fle->fd);
	if (sk < 0) {
		pr_err("Can't recv pair slave");
		return -1;
	}
	close(fle->fd);

	if (bind_unix_sk(sk, ui))
		return -1;

	return sk;
}

static int open_unixsk_standalone(struct unix_sk_info *ui)
{
	int sk;

	pr_info("Opening standalone socket (id 0x%x peer 0x%x)\n",
			ui->ue.id, ui->ue.peer);

	sk = socket(PF_UNIX, ui->ue.type, 0);
	if (sk < 0) {
		pr_perror("Can't make unix socket");
		return -1;
	}

	if (restore_fown(sk, &ui->ue.fown))
		return -1;

	if (bind_unix_sk(sk, ui))
		return -1;

	if (ui->ue.state == TCP_LISTEN) {
		pr_info("\tPutting 0x%x into listen state\n", ui->ue.id);
		if (listen(sk, ui->ue.backlog) < 0) {
			pr_perror("Can't make usk listen");
			return -1;
		}
	} else if (ui->peer) {
		pr_info("\tWill connect 0x%x to 0x%x later\n", ui->ue.id, ui->ue.peer);
		if (schedule_conn_job(ui))
			return -1;
	}

	return sk;
}

static int open_unix_sk(struct file_desc *d)
{
	struct unix_sk_info *ui;

	ui = container_of(d, struct unix_sk_info, d);
	if (ui->flags & USK_PAIR_MASTER)
		return open_unixsk_pair_master(ui);
	else if (ui->flags & USK_PAIR_SLAVE)
		return open_unixsk_pair_slave(ui);
	else
		return open_unixsk_standalone(ui);
}

static struct file_desc_ops unix_desc_ops = {
	.open = open_unix_sk,
	.want_transport = unixsk_should_open_transport,
};

int collect_unix_sockets(void)
{
	int fd, ret;

	pr_info("Reading unix sockets in\n");

	fd = open_image_ro(CR_FD_UNIXSK);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		else
			return -1;
	}

	while (1) {
		struct unix_sk_info *ui;

		ui = xmalloc(sizeof(*ui));
		ret = -1;
		if (ui == NULL)
			break;

		ret = read_img_eof(fd, &ui->ue);
		if (ret <= 0) {
			xfree(ui);
			break;
		}

		if (ui->ue.namelen) {
			ret = -1;

			if (!ui->ue.namelen || ui->ue.namelen >= UNIX_PATH_MAX) {
				pr_err("Bad unix name len %d\n", ui->ue.namelen);
				break;
			}

			ui->name = xmalloc(ui->ue.namelen);
			if (ui->name == NULL)
				break;

			ret = read_img_buf(fd, ui->name, ui->ue.namelen);
			if (ret < 0)
				break;

			/*
			 * Make FS clean from sockets we're about to
			 * restore. See for how we bind them for details
			 */
			if (ui->name[0] != '\0')
				unlink(ui->name);
		} else
			ui->name = NULL;

		ui->peer = NULL;
		ui->flags = 0;
		pr_info(" `- Got %u peer %u\n", ui->ue.id, ui->ue.peer);
		file_desc_add(&ui->d, FDINFO_UNIXSK, ui->ue.id,
				&unix_desc_ops);
		list_add_tail(&ui->list, &unix_sockets);
	}

	close(fd);

	return read_sockets_queues();
}

int resolve_unix_peers(void)
{
	struct unix_sk_info *ui, *peer;
	struct fdinfo_list_entry *fle, *fle_peer;

	list_for_each_entry(ui, &unix_sockets, list) {
		if (ui->peer)
			continue;
		if (!ui->ue.peer)
			continue;

		peer = find_unix_sk(ui->ue.peer);
		if (!peer) {
			pr_err("FATAL: Peer 0x%x unresolved for 0x%x\n",
					ui->ue.peer, ui->ue.id);
			return -1;
		}

		ui->peer = peer;
		if (ui == peer)
			/* socket connected to self %) */
			continue;
		if (peer->ue.peer != ui->ue.id)
			continue;

		/* socketpair or interconnected sockets */
		peer->peer = ui;

		/*
		 * Select who will restore the pair. Check is identical to
		 * the one in pipes.c and makes sure tasks wait for each other
		 * in pids sorting order (ascending).
		 */

		fle = file_master(&ui->d);
		fle_peer = file_master(&peer->d);

		if ((fle->pid < fle_peer->pid) ||
				(fle->pid == fle_peer->pid &&
				 fle->fd < fle_peer->fd)) {
			ui->flags |= USK_PAIR_MASTER;
			peer->flags |= USK_PAIR_SLAVE;
		} else {
			peer->flags |= USK_PAIR_MASTER;
			ui->flags |= USK_PAIR_SLAVE;
		}
	}

	pr_info("Unix sockets:\n");
	list_for_each_entry(ui, &unix_sockets, list) {
		struct fdinfo_list_entry *fle;

		pr_info("\t0x%x -> 0x%x (0x%x) flags 0x%x\n", ui->ue.id, ui->ue.peer,
				ui->peer ? ui->peer->ue.id : 0, ui->flags);
		list_for_each_entry(fle, &ui->d.fd_info_head, list)
			pr_info("\t\tfd %d in pid %d\n",
					fle->fd, fle->pid);

	}

	return 0;
}
