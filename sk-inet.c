#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#include "types.h"
#include "libnetlink.h"
#include "crtools.h"
#include "inet_diag.h"
#include "files.h"
#include "image.h"
#include "log.h"
#include "util.h"
#include "sockets.h"
#include "sk-inet.h"

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

#define tcp_connection(sk)	(((sk)->proto == IPPROTO_TCP) &&	\
				 ((sk)->state == TCP_ESTABLISHED))

static struct inet_sk_desc *gen_uncon_sk(int lfd, const struct fd_parms *p)
{
	struct inet_sk_desc *sk;
	char address[128];
	socklen_t aux;
	int ret;

	sk = xzalloc(sizeof(*sk));
	if (!sk)
		goto err;

	/* It should has no peer name */
	aux = sizeof(address);
	ret = getsockopt(lfd, SOL_SOCKET, SO_PEERNAME, address, &aux);
	if (ret != -1 || errno != ENOTCONN) {
		pr_err("Errno %d returned from unconnected socket\n", errno);
		goto err;
	}

	sk->sd.ino = p->stat.st_ino;

	ret  = do_dump_opt(lfd, SO_DOMAIN, &sk->sd.family, sizeof(sk->sd.family));
	ret |= do_dump_opt(lfd, SO_TYPE, &sk->type, sizeof(sk->type));
	ret |= do_dump_opt(lfd, SO_PROTOCOL, &sk->proto, sizeof(sk->proto));
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

static int dump_one_inet_fd(int lfd, u32 id, const struct fd_parms *p)
{
	struct inet_sk_desc *sk;
	InetSkEntry ie = INET_SK_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	int ret = -1;

	sk = (struct inet_sk_desc *)lookup_socket(p->stat.st_ino);
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
	ie.family	= sk->sd.family;
	ie.type		= sk->type;
	ie.proto	= sk->proto;
	ie.state	= sk->state;
	ie.src_port	= sk->src_port;
	ie.dst_port	= sk->dst_port;
	ie.backlog	= sk->wqlen;
	ie.flags	= p->flags;

	ie.fown		= (FownEntry *)&p->fown;
	ie.opts		= &skopts;

	ie.n_src_addr = 4;
	ie.n_dst_addr = 4;

	ie.src_addr = xmalloc(pb_repeated_size(&ie, src_addr));
	ie.dst_addr = xmalloc(pb_repeated_size(&ie, dst_addr));

	if (!ie.src_addr || !ie.dst_addr)
		goto err;

	memcpy(ie.src_addr, sk->src_addr, sizeof(u32) * 4);
	memcpy(ie.dst_addr, sk->dst_addr, sizeof(u32) * 4);

	if (dump_socket_opts(lfd, &skopts))
		goto err;

	if (pb_write(fdset_fd(glob_fdset, CR_FD_INETSK), &ie, inet_sk_entry))
		goto err;

	pr_info("Dumping inet socket at %d\n", p->fd);
	show_one_inet("Dumping", sk);
	show_one_inet_img("Dumped", &ie);
	sk->sd.already_dumped = 1;

	if (tcp_connection(sk))
		ret = dump_one_tcp(lfd, sk);
	else
		ret = 0;
err:
	xfree(ie.src_addr);
	xfree(ie.dst_addr);
	return ret;
}

static const struct fdtype_ops inet_dump_ops = {
	.type		= FD_TYPES__INETSK,
	.make_gen_id	= make_gen_id,
	.dump		= dump_one_inet_fd,
};

int dump_one_inet(struct fd_parms *p, int lfd, const struct cr_fdset *set)
{
	return do_dump_gen_file(p, lfd, &inet_dump_ops, set);
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

	ret = sk_collect_one(m->idiag_inode, family, &d->sd);

	show_one_inet("Collected", d);

	return ret;
}

static u32 zero_addr[4];

static bool is_bound(struct inet_sk_info *ii)
{
	BUG_ON(sizeof(zero_addr) <
		     max(pb_repeated_size(ii->ie, dst_addr),
			 pb_repeated_size(ii->ie, src_addr)));

	return memcmp(zero_addr, ii->ie->src_addr, pb_repeated_size(ii->ie, src_addr)) ||
	       memcmp(zero_addr, ii->ie->dst_addr, pb_repeated_size(ii->ie, dst_addr));
}


static int open_inet_sk(struct file_desc *d);

static struct file_desc_ops inet_desc_ops = {
	.type = FD_TYPES__INETSK,
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

		ret = pb_read_eof(fd, &ii->ie, inet_sk_entry);
		if (ret <= 0)
			break;

		file_desc_add(&ii->d, ii->ie->id, &inet_desc_ops);

		if (tcp_connection(ii->ie))
			tcp_locked_conn_add(ii);
	}

	if (ii)
		xfree(ii);

	close(fd);
	return ret;
}

static int open_inet_sk(struct file_desc *d)
{
	struct inet_sk_info *ii;
	int sk;

	ii = container_of(d, struct inet_sk_info, d);

	show_one_inet_img("Restore", ii->ie);

	if (ii->ie->family != AF_INET && ii->ie->family != AF_INET6) {
		pr_err("Unsupported socket family: %d\n", ii->ie->family);
		return -1;
	}

	if ((ii->ie->type != SOCK_STREAM) && (ii->ie->type != SOCK_DGRAM)) {
		pr_err("Unsupported socket type: %d\n", ii->ie->type);
		return -1;
	}

	sk = socket(ii->ie->family, ii->ie->type, ii->ie->proto);
	if (sk < 0) {
		pr_perror("Can't create unix socket");
		return -1;
	}

	if (tcp_connection(ii->ie)) {
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

	if (is_bound(ii)) {
		if (inet_bind(sk, ii))
			goto err;
	}

	if (ii->ie->state == TCP_LISTEN) {
		if (ii->ie->proto != IPPROTO_TCP) {
			pr_err("Wrong socket in listen state %d\n", ii->ie->proto);
			goto err;
		}

		if (listen(sk, ii->ie->backlog) == -1) {
			pr_perror("Can't listen on a socket");
			goto err;
		}
	}

	if (ii->ie->state == TCP_ESTABLISHED &&
			inet_connect(sk, ii))
		goto err;
done:
	if (rst_file_params(sk, ii->ie->fown, ii->ie->flags))
		goto err;

	if (restore_socket_opts(sk, ii->ie->opts))
		return -1;

	return sk;

err:
	close(sk);
	return -1;
}

int inet_bind(int sk, struct inet_sk_info *ii)
{
	union {
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} addr;
	int addr_size;


	memzero(&addr, sizeof(addr));
	if (ii->ie->family == AF_INET) {
		BUG_ON(pb_repeated_size(ii->ie, src_addr) < sizeof(addr.v4.sin_addr.s_addr));

		addr.v4.sin_family = ii->ie->family;
		addr.v4.sin_port = htons(ii->ie->src_port);
		memcpy(&addr.v4.sin_addr.s_addr, ii->ie->src_addr, sizeof(addr.v4.sin_addr.s_addr));
		addr_size = sizeof(addr.v4);
	} else if (ii->ie->family == AF_INET6) {
		BUG_ON(pb_repeated_size(ii->ie, src_addr) < sizeof(addr.v6.sin6_addr.s6_addr));

		addr.v6.sin6_family = ii->ie->family;
		addr.v6.sin6_port = htons(ii->ie->src_port);
		memcpy(&addr.v6.sin6_addr.s6_addr, ii->ie->src_addr, sizeof(addr.v6.sin6_addr.s6_addr));
		addr_size = sizeof(addr.v6);
	} else
		BUG_ON(1);

	if (bind(sk, (struct sockaddr *)&addr, addr_size) == -1) {
		pr_perror("Can't bind inet socket");
		return -1;
	}

	return 0;
}

int inet_connect(int sk, struct inet_sk_info *ii)
{
	union {
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} addr;
	int addr_size;


	memzero(&addr, sizeof(addr));
	if (ii->ie->family == AF_INET) {
		BUG_ON(pb_repeated_size(ii->ie, dst_addr) < sizeof(addr.v4.sin_addr.s_addr));

		addr.v4.sin_family = ii->ie->family;
		addr.v4.sin_port = htons(ii->ie->dst_port);
		memcpy(&addr.v4.sin_addr.s_addr, ii->ie->dst_addr, sizeof(addr.v4.sin_addr.s_addr));
		addr_size = sizeof(addr.v4);
	} else if (ii->ie->family == AF_INET6) {
		BUG_ON(pb_repeated_size(ii->ie, dst_addr) < sizeof(addr.v6.sin6_addr.s6_addr));

		addr.v6.sin6_family = ii->ie->family;
		addr.v6.sin6_port = htons(ii->ie->dst_port);
		memcpy(&addr.v6.sin6_addr.s6_addr, ii->ie->dst_addr, sizeof(addr.v6.sin6_addr.s6_addr));
		addr_size = sizeof(addr.v6);
	} else
		BUG_ON(1);

	if (connect(sk, (struct sockaddr *)&addr, addr_size) == -1) {
		pr_perror("Can't connect inet socket back");
		return -1;
	}

	return 0;
}

void show_inetsk(int fd, struct cr_options *o)
{
	InetSkEntry *ie;
	int ret = 0;

	pr_img_head(CR_FD_INETSK);

	while (1) {
		char src_addr[INET_ADDR_LEN] = "<unknown>";
		char dst_addr[INET_ADDR_LEN] = "<unknown>";

		ret = pb_read_eof(fd, &ie, inet_sk_entry);
		if (ret <= 0)
			goto out;

		if (inet_ntop(ie->family, (void *)ie->src_addr, src_addr,
			      INET_ADDR_LEN) == NULL) {
			pr_perror("Failed to translate src address");
		}

		if (ie->state == TCP_ESTABLISHED) {
			if (inet_ntop(ie->family, (void *)ie->dst_addr, dst_addr,
				      INET_ADDR_LEN) == NULL) {
				pr_perror("Failed to translate dst address");
			}
		}

		pr_msg("id %#x ino %#x family %s type %s proto %s state %s %s:%d <-> %s:%d flags 0x%2x\n",
			ie->id, ie->ino, skfamily2s(ie->family), sktype2s(ie->type), skproto2s(ie->proto),
			skstate2s(ie->state), src_addr, ie->src_port, dst_addr, ie->dst_port, ie->flags);
		pr_msg("\t"), show_fown_cont(ie->fown), pr_msg("\n");
		show_socket_opts(ie->opts);

		inet_sk_entry__free_unpacked(ie, NULL);
	}

out:
	if (ret)
		pr_info("\n");
	pr_img_tail(CR_FD_INETSK);
}

