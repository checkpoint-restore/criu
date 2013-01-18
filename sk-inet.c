#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/mman.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#include "asm/types.h"
#include "libnetlink.h"
#include "crtools.h"
#include "inet_diag.h"
#include "files.h"
#include "image.h"
#include "log.h"
#include "util.h"
#include "sockets.h"
#include "sk-inet.h"

#define PB_ALEN_INET	1
#define PB_ALEN_INET6	4

static LIST_HEAD(inet_ports);

struct inet_port {
	int port;
	int type;
	futex_t users;
	struct list_head list;
};

static struct inet_port *port_add(int type, int port)
{
	struct inet_port *e;

	list_for_each_entry(e, &inet_ports, list)
		if (e->type == type && e->port == port) {
			futex_inc(&e->users);
			return e;
		}

	e = shmalloc(sizeof(*e));
	if (e == NULL) {
		pr_err("Not enough memory\n");
		return NULL;
	}

	e->port = port;
	e->type = type;
	futex_init(&e->users);
	futex_inc(&e->users);

	list_add(&e->list, &inet_ports);

	return e;
}

static void show_one_inet(const char *act, const struct inet_sk_desc *sk)
{
	char src_addr[INET_ADDR_LEN] = "<unknown>";

	if (inet_ntop(sk->sd.family, (void *)sk->src_addr, src_addr,
		      INET_ADDR_LEN) == NULL) {
		pr_perror("Failed to translate address");
	}

	pr_debug("\t%s: ino 0x%8x family %4d type %4d port %8d "
		"state %2d src_addr %s\n",
		act, sk->sd.ino, sk->sd.family, sk->type, sk->src_port,
		sk->state, src_addr);
}

static void show_one_inet_img(const char *act, const InetSkEntry *e)
{
	char src_addr[INET_ADDR_LEN] = "<unknown>";

	if (inet_ntop(e->family, (void *)e->src_addr, src_addr,
		      INET_ADDR_LEN) == NULL) {
		pr_perror("Failed to translate address");
	}

	pr_debug("\t%s: family %d type %d proto %d port %d "
		"state %d src_addr %s\n",
		act, e->family, e->type, e->proto, e->src_port,
		e->state, src_addr);
}

static int can_dump_inet_sk(const struct inet_sk_desc *sk)
{
	if (sk->sd.family != AF_INET && sk->sd.family != AF_INET6) {
		pr_err("Only IPv4/6 sockets for now\n");
		return 0;
	}

	if (sk->shutdown) {
		pr_err("Can't dump shutdown inet socket\n");
		return 0;
	}

	if (sk->type == SOCK_DGRAM) {
		if (sk->wqlen != 0) {
			pr_err("Can't dump corked dgram socket\n");
			return 0;
		}

		if (sk->rqlen)
			pr_warn("Read queue is dropped for socket %x\n",
					sk->sd.ino);

		return 1;
	}

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
	case TCP_ESTABLISHED:
		if (!opts.tcp_established_ok) {
			pr_err("Connected TCP socket, consider using %s option.\n",
					SK_EST_PARAM);
			return 0;
		}
		break;
	case TCP_CLOSE:
		/* Trivial case, we just need to create a socket on restore */
		break;
	default:
		pr_err("Unknown state %d\n", sk->state);
		return 0;
	}

	/* Make sure it's a proto we support */
	switch (sk->proto) {
	case IPPROTO_IP:
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		break;
	default:
		pr_err("Unsupported socket proto %d\n", sk->proto);
		return 0;
	}

	return 1;
}

static struct inet_sk_desc *gen_uncon_sk(int lfd, const struct fd_parms *p)
{
	struct inet_sk_desc *sk;
	char address;
	socklen_t aux;
	int ret;

	sk = xzalloc(sizeof(*sk));
	if (!sk)
		goto err;

	/* It should has no peer name */
	aux = sizeof(address);
	ret = getsockopt(lfd, SOL_SOCKET, SO_PEERNAME, &address, &aux);
	if (ret < 0) {
		if (errno != ENOTCONN) {
			pr_perror("Unexpected error returned from unconnected socket");
			goto err;
		}
	} else if (ret == 0) {
		pr_err("Name resolved on unconnected socket\n");
		goto err;
	}

	sk->sd.ino = p->stat.st_ino;

	ret  = do_dump_opt(lfd, SOL_SOCKET, SO_DOMAIN, &sk->sd.family, sizeof(sk->sd.family));
	ret |= do_dump_opt(lfd, SOL_SOCKET, SO_TYPE, &sk->type, sizeof(sk->type));
	ret |= do_dump_opt(lfd, SOL_SOCKET, SO_PROTOCOL, &sk->proto, sizeof(sk->proto));
	if (ret)
		goto err;

	if (sk->proto == IPPROTO_TCP) {
		struct tcp_info info;

		aux = sizeof(info);
		ret = getsockopt(lfd, SOL_TCP, TCP_INFO, &info, &aux);
		if (ret) {
			pr_perror("Failt to obtain TCP_INFO");
			goto err;
		}

		if (info.tcpi_state != TCP_CLOSE) {
			pr_err("Socket state %d obtained but expected %d\n",
			       info.tcpi_state, TCP_CLOSE);
			goto err;
		}

		sk->wqlen = info.tcpi_backoff;
	}

	sk->state = TCP_CLOSE;

	sk_collect_one(sk->sd.ino, sk->sd.family, &sk->sd);

	return sk;
err:
	xfree(sk);
	return NULL;
}

static int do_dump_one_inet_fd(int lfd, u32 id, const struct fd_parms *p, int family)
{
	struct inet_sk_desc *sk;
	InetSkEntry ie = INET_SK_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	int ret = -1;

	sk = (struct inet_sk_desc *)lookup_socket(p->stat.st_ino, family);
	if (!sk) {
		sk = gen_uncon_sk(lfd, p);
		if (!sk)
			goto err;
	}

	if (!can_dump_inet_sk(sk))
		goto err;

	BUG_ON(sk->sd.already_dumped);

	ie.id		= id;
	ie.ino		= sk->sd.ino;
	ie.family	= family;
	ie.type		= sk->type;
	ie.proto	= sk->proto;
	ie.state	= sk->state;
	ie.src_port	= sk->src_port;
	ie.dst_port	= sk->dst_port;
	ie.backlog	= sk->wqlen;
	ie.flags	= p->flags;

	ie.fown		= (FownEntry *)&p->fown;
	ie.opts		= &skopts;

	ie.n_src_addr = PB_ALEN_INET;
	ie.n_dst_addr = PB_ALEN_INET;
	if (ie.family == AF_INET6) {
		int val;

		ie.n_src_addr = PB_ALEN_INET6;
		ie.n_dst_addr = PB_ALEN_INET6;

		ret = dump_opt(lfd, SOL_IPV6, IPV6_V6ONLY, &val);
		if (ret < 0)
			goto err;

		ie.v6only = val ? true : false;
		ie.has_v6only = true;
	}

	ie.src_addr = xmalloc(pb_repeated_size(&ie, src_addr));
	ie.dst_addr = xmalloc(pb_repeated_size(&ie, dst_addr));

	if (!ie.src_addr || !ie.dst_addr)
		goto err;

	memcpy(ie.src_addr, sk->src_addr, pb_repeated_size(&ie, src_addr));
	memcpy(ie.dst_addr, sk->dst_addr, pb_repeated_size(&ie, dst_addr));

	if (dump_socket_opts(lfd, &skopts))
		goto err;

	if (pb_write_one(fdset_fd(glob_fdset, CR_FD_INETSK), &ie, PB_INETSK))
		goto err;

	pr_info("Dumping inet socket at %d\n", p->fd);
	show_one_inet("Dumping", sk);
	show_one_inet_img("Dumped", &ie);
	sk->sd.already_dumped = 1;

	switch (sk->proto) {
	case IPPROTO_TCP:
		ret = dump_one_tcp(lfd, sk);
		break;
	default:
		ret = 0;
		break;
	}
err:
	release_skopts(&skopts);
	xfree(ie.src_addr);
	xfree(ie.dst_addr);
	return ret;
}

static int dump_one_inet_fd(int lfd, u32 id, const struct fd_parms *p)
{
	return do_dump_one_inet_fd(lfd, id, p, PF_INET);
}

static const struct fdtype_ops inet_dump_ops = {
	.type		= FD_TYPES__INETSK,
	.dump		= dump_one_inet_fd,
};

int dump_one_inet(struct fd_parms *p, int lfd, const int fdinfo)
{
	return do_dump_gen_file(p, lfd, &inet_dump_ops, fdinfo);
}

static int dump_one_inet6_fd(int lfd, u32 id, const struct fd_parms *p)
{
	return do_dump_one_inet_fd(lfd, id, p, PF_INET6);
}

static const struct fdtype_ops inet6_dump_ops = {
	.type		= FD_TYPES__INETSK,
	.dump		= dump_one_inet6_fd,
};

int dump_one_inet6(struct fd_parms *p, int lfd, const int fdinfo)
{
	return do_dump_gen_file(p, lfd, &inet6_dump_ops, fdinfo);
}

int inet_collect_one(struct nlmsghdr *h, int family, int type, int proto)
{
	struct inet_sk_desc *d;
	struct inet_diag_msg *m = NLMSG_DATA(h);
	struct rtattr *tb[INET_DIAG_MAX+1];
	int ret;

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

	if (tb[INET_DIAG_SHUTDOWN])
		d->shutdown = *(u8 *)RTA_DATA(tb[INET_DIAG_SHUTDOWN]);
	else
		pr_err_once("Can't check shutdown state of inet socket\n");

	ret = sk_collect_one(m->idiag_inode, family, &d->sd);

	show_one_inet("Collected", d);

	return ret;
}

static int open_inet_sk(struct file_desc *d);
static int post_open_inet_sk(struct file_desc *d, int sk);

static struct file_desc_ops inet_desc_ops = {
	.type = FD_TYPES__INETSK,
	.open = open_inet_sk,
	.post_open = post_open_inet_sk,
};

static inline int tcp_connection(InetSkEntry *ie)
{
	return (ie->proto == IPPROTO_TCP) && (ie->state == TCP_ESTABLISHED);
}

static int collect_one_inetsk(void *o, ProtobufCMessage *base)
{
	struct inet_sk_info *ii = o;

	ii->ie = pb_msg(base, InetSkEntry);
	file_desc_add(&ii->d, ii->ie->id, &inet_desc_ops);
	if (tcp_connection(ii->ie))
		tcp_locked_conn_add(ii);

	/*
	 * A socket can reuse addr only if all previous sockets allow that,
	 * so a value of SO_REUSEADDR can be restored after restoring all
	 * sockets.
	 */
	ii->port = port_add(ii->ie->type, ii->ie->src_port);
	if (ii->port == NULL)
		return -1;

	return 0;
}

int collect_inet_sockets(void)
{
	return collect_image(CR_FD_INETSK, PB_INETSK,
			sizeof(struct inet_sk_info), collect_one_inetsk);
}

static int inet_validate_address(InetSkEntry *ie)
{
	if ((ie->family == AF_INET) &&
			/* v0.1 had 4 in ipv4 addr len */
			(ie->n_src_addr >= PB_ALEN_INET) &&
			(ie->n_dst_addr >= PB_ALEN_INET))
		return 0;

	if ((ie->family == AF_INET6) &&
			(ie->n_src_addr == PB_ALEN_INET6) &&
			(ie->n_dst_addr == PB_ALEN_INET6))
		return 0;

	pr_err("Addr len mismatch f %d ss %zu ds %zu\n", ie->family,
			pb_repeated_size(ie, src_addr),
			pb_repeated_size(ie, dst_addr));

	return -1;
}

static int post_open_inet_sk(struct file_desc *d, int sk)
{
	struct inet_sk_info *ii;
	int val;

	ii = container_of(d, struct inet_sk_info, d);

	/*
	 * TCP sockets are handled at the last moment
	 * after unlocking connections.
	 */
	if (tcp_connection(ii->ie))
		return 0;

	/* SO_REUSEADDR is set for all sockets */
	if (ii->ie->opts->reuseaddr)
		return 0;

	futex_wait_until(&ii->port->users, 0);

	val = ii->ie->opts->reuseaddr;
	if (restore_opt(sk, SOL_SOCKET, SO_REUSEADDR, &val))
		return -1;

	return 0;
}

static int open_inet_sk(struct file_desc *d)
{
	struct inet_sk_info *ii;
	InetSkEntry *ie;
	int sk, yes = 1;

	ii = container_of(d, struct inet_sk_info, d);
	ie = ii->ie;

	show_one_inet_img("Restore", ie);

	if (ie->family != AF_INET && ie->family != AF_INET6) {
		pr_err("Unsupported socket family: %d\n", ie->family);
		return -1;
	}

	if ((ie->type != SOCK_STREAM) && (ie->type != SOCK_DGRAM)) {
		pr_err("Unsupported socket type: %d\n", ie->type);
		return -1;
	}

	if (inet_validate_address(ie))
		return -1;

	sk = socket(ie->family, ie->type, ie->proto);
	if (sk < 0) {
		pr_perror("Can't create unix socket");
		return -1;
	}

	if (ie->v6only) {
		if (restore_opt(sk, SOL_IPV6, IPV6_V6ONLY, &yes) == -1)
			return -1;
	}

	/*
	 * Set SO_REUSEADDR, because some sockets can be bound to one addr.
	 * The origin value of SO_REUSEADDR will be restored in post_open.
	 */
	if (restore_opt(sk, SOL_SOCKET, SO_REUSEADDR, &yes))
		return -1;

	if (tcp_connection(ie)) {
		if (!opts.tcp_established_ok) {
			pr_err("Connected TCP socket in image\n");
			goto err;
		}

		if (restore_one_tcp(sk, ii))
			goto err;

		goto done;
	}

	/*
	 * Listen sockets are easiest ones -- simply
	 * bind() and listen(), and that's all.
	 */

	if (ie->src_port) {
		if (inet_bind(sk, ii))
			goto err;
	}

	if (ie->state == TCP_LISTEN) {
		if (ie->proto != IPPROTO_TCP) {
			pr_err("Wrong socket in listen state %d\n", ie->proto);
			goto err;
		}

		if (listen(sk, ie->backlog) == -1) {
			pr_perror("Can't listen on a socket");
			goto err;
		}
	}

	if (ie->state == TCP_ESTABLISHED &&
			inet_connect(sk, ii))
		goto err;
done:
	futex_dec(&ii->port->users);

	if (rst_file_params(sk, ie->fown, ie->flags))
		goto err;

	if (restore_socket_opts(sk, ie->opts))
		return -1;

	return sk;

err:
	close(sk);
	return -1;
}

union sockaddr_inet {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

static int restore_sockaddr(union sockaddr_inet *sa,
		int family, uint32_t pb_port, uint32_t *pb_addr)
{
	BUILD_BUG_ON(sizeof(sa->v4.sin_addr.s_addr) > PB_ALEN_INET * sizeof(uint32_t));
	BUILD_BUG_ON(sizeof(sa->v6.sin6_addr.s6_addr) > PB_ALEN_INET6 * sizeof(uint32_t));

	memzero(sa, sizeof(*sa));

	if (family == AF_INET) {
		sa->v4.sin_family = AF_INET;
		sa->v4.sin_port = htons(pb_port);
		memcpy(&sa->v4.sin_addr.s_addr, pb_addr, sizeof(sa->v4.sin_addr.s_addr));
		return sizeof(sa->v4);
	}

	if (family == AF_INET6) {
		sa->v6.sin6_family = AF_INET6;
		sa->v6.sin6_port = htons(pb_port);
		memcpy(sa->v6.sin6_addr.s6_addr, pb_addr, sizeof(sa->v6.sin6_addr.s6_addr));
		return sizeof(sa->v6);
	}

	BUG();
	return -1;
}

int inet_bind(int sk, struct inet_sk_info *ii)
{
	union sockaddr_inet addr;
	int addr_size;

	addr_size = restore_sockaddr(&addr, ii->ie->family,
			ii->ie->src_port, ii->ie->src_addr);

	if (bind(sk, (struct sockaddr *)&addr, addr_size) == -1) {
		pr_perror("Can't bind inet socket");
		return -1;
	}

	return 0;
}

int inet_connect(int sk, struct inet_sk_info *ii)
{
	union sockaddr_inet addr;
	int addr_size;

	addr_size = restore_sockaddr(&addr, ii->ie->family,
			ii->ie->dst_port, ii->ie->dst_addr);

	if (connect(sk, (struct sockaddr *)&addr, addr_size) == -1) {
		pr_perror("Can't connect inet socket back");
		return -1;
	}

	return 0;
}

void show_inetsk(int fd, struct cr_options *o)
{
	pb_show_plain_pretty(fd, PB_INETSK, "1:%#x 2:%#x 3:%d 4:%d 5:%d 6:%d 7:%d 8:%d 9:%2x 11:A 12:A");
}
