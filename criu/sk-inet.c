#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <libnl3/netlink/msg.h>
#include <net/if.h>
#include <sys/mman.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#include "../soccr/soccr.h"

#include "libnetlink.h"
#include "cr_options.h"
#include "imgset.h"
#include "inet_diag.h"
#include "files.h"
#include "image.h"
#include "log.h"
#include "rst-malloc.h"
#include "sockets.h"
#include "sk-inet.h"
#include "protobuf.h"
#include "util.h"

#define PB_ALEN_INET	1
#define PB_ALEN_INET6	4

static LIST_HEAD(inet_ports);

struct inet_port {
	int port;
	int type;
	struct list_head type_list;
	atomic_t users;
	mutex_t reuseaddr_lock;
	struct list_head list;
};

static struct inet_port *port_add(struct inet_sk_info *ii, int port)
{
	int type = ii->ie->type;
	struct inet_port *e;

	list_for_each_entry(e, &inet_ports, list)
		if (e->type == type && e->port == port) {
			atomic_inc(&e->users);
			goto out_link;
		}

	e = shmalloc(sizeof(*e));
	if (e == NULL) {
		pr_err("Not enough memory\n");
		return NULL;
	}

	e->port = port;
	e->type = type;
	atomic_set(&e->users, 1);
	mutex_init(&e->reuseaddr_lock);
	INIT_LIST_HEAD(&e->type_list);

	list_add(&e->list, &inet_ports);
out_link:
	list_add(&ii->port_list, &e->type_list);

	return e;
}

static void show_one_inet(const char *act, const struct inet_sk_desc *sk)
{
	char src_addr[INET_ADDR_LEN] = "<unknown>";

	if (inet_ntop(sk->sd.family, (void *)sk->src_addr, src_addr,
		      INET_ADDR_LEN) == NULL) {
		pr_perror("Failed to translate address");
	}

	pr_debug("\t%s: ino %#8x family %4d type %4d port %8d "
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

static int can_dump_ipproto(int ino, int proto)
{
	/* Make sure it's a proto we support */
	switch (proto) {
	case IPPROTO_IP:
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		break;
	default:
		pr_err("Unsupported proto %d for socket %x\n", proto, ino);
		return 0;
	}

	return 1;
}

static int can_dump_inet_sk(const struct inet_sk_desc *sk)
{
	BUG_ON((sk->sd.family != AF_INET) && (sk->sd.family != AF_INET6));

	if (sk->type == SOCK_DGRAM) {
		if (sk->shutdown) {
			pr_err("Can't dump shutdown inet socket %x\n",
					sk->sd.ino);
			return 0;
		}

		if (sk->wqlen != 0) {
			pr_err("Can't dump corked dgram socket %x\n",
					sk->sd.ino);
			return 0;
		}

		if (sk->rqlen)
			pr_warn("Read queue is dropped for socket %x\n",
					sk->sd.ino);

		return 1;
	}

	if (sk->type != SOCK_STREAM) {
		pr_err("Can't dump %d inet socket %x. "
				"Only can stream and dgram.\n",
				sk->type, sk->sd.ino);
		return 0;
	}

	switch (sk->state) {
	case TCP_LISTEN:
		if (sk->rqlen != 0) {
			if (opts.tcp_skip_in_flight) {
				pr_info("Skipping in-flight connection (l) for %x\n",
						sk->sd.ino);
				break;
			}
			/*
			 * Currently the ICONS nla reports the conn
			 * requests for listen sockets. Need to pick
			 * those up and fix the connect job respectively
			 */
			pr_err("In-flight connection (l) for %x\n",
					sk->sd.ino);
			pr_err("In-flight connections can be ignored with the "
					"--%s option.\n", SK_INFLIGHT_PARAM);
			return 0;
		}
		break;
	case TCP_ESTABLISHED:
	case TCP_FIN_WAIT2:
	case TCP_FIN_WAIT1:
	case TCP_CLOSE_WAIT:
	case TCP_LAST_ACK:
	case TCP_CLOSING:
	case TCP_SYN_SENT:
		if (!opts.tcp_established_ok) {
			pr_err("Connected TCP socket, consider using --%s option.\n",
					SK_EST_PARAM);
			return 0;
		}
		break;
	case TCP_CLOSE:
		/* Trivial case, we just need to create a socket on restore */
		break;
	default:
		pr_err("Unknown inet socket %x state %d\n", sk->sd.ino, sk->state);
		return 0;
	}

	return 1;
}

static int dump_sockaddr(union libsoccr_addr *sa, u32 *pb_port, u32 *pb_addr)
{
	if (sa->sa.sa_family == AF_INET) {
		memcpy(pb_addr, &sa->v4.sin_addr, sizeof(sa->v4.sin_addr));
		*pb_port = ntohs(sa->v4.sin_port);
		return 0;
	} if (sa->sa.sa_family == AF_INET6) {
		*pb_port = ntohs(sa->v6.sin6_port);
		memcpy(pb_addr, &sa->v6.sin6_addr, sizeof(sa->v6.sin6_addr));
		return 0;
	}
	return -1;
}

static struct inet_sk_desc *gen_uncon_sk(int lfd, const struct fd_parms *p, int proto)
{
	struct inet_sk_desc *sk;
	union libsoccr_addr address;
	socklen_t aux;
	int ret;

	sk = xzalloc(sizeof(*sk));
	if (!sk)
		goto err;

	ret  = do_dump_opt(lfd, SOL_SOCKET, SO_DOMAIN, &sk->sd.family, sizeof(sk->sd.family));
	ret |= do_dump_opt(lfd, SOL_SOCKET, SO_TYPE, &sk->type, sizeof(sk->type));
	if (ret)
		goto err;

	if (sk->sd.family == AF_INET)
		aux = sizeof(struct sockaddr_in);
	else if (sk->sd.family == AF_INET6)
		aux = sizeof(struct sockaddr_in6);
	else {
		pr_err("Unsupported socket family: %d\n", sk->sd.family);
		goto err;
	}

	ret = getsockopt(lfd, SOL_SOCKET, SO_PEERNAME, &address, &aux);
	if (ret < 0) {
		if (errno != ENOTCONN) {
			pr_perror("Unexpected error returned from unconnected socket");
			goto err;
		}
	} else if (dump_sockaddr(&address, &sk->dst_port, sk->dst_addr))
		goto err;

	ret = getsockname(lfd, &address.sa, &aux);
	if (ret < 0) {
		if (errno != ENOTCONN) {
			pr_perror("Unexpected error returned from unconnected socket");
			goto err;
		}
	} else if (dump_sockaddr(&address, &sk->src_port, sk->src_addr))
		goto err;

	sk->sd.ino = p->stat.st_ino;

	if (proto == IPPROTO_TCP) {
		struct tcp_info info;

		aux = sizeof(info);
		ret = getsockopt(lfd, SOL_TCP, TCP_INFO, &info, &aux);
		if (ret) {
			pr_perror("Failed to obtain TCP_INFO");
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

static int dump_ip_opts(int sk, IpOptsEntry *ioe)
{
	int ret = 0;

	ret |= dump_opt(sk, SOL_IP, IP_FREEBIND, &ioe->freebind);
	ioe->has_freebind = ioe->freebind;

	return ret;
}

/* Stolen from the kernel's __ipv6_addr_type/__ipv6_addr_needs_scopeid;
 * link local and (multicast + loopback + linklocal) addrs require a
 * scope id.
 */
#define IPV6_ADDR_SCOPE_NODELOCAL       0x01
#define IPV6_ADDR_SCOPE_LINKLOCAL       0x02
static bool needs_scope_id(uint32_t *src_addr)
{
	if ((src_addr[0] & htonl(0xFF00000)) == htonl(0xFF000000)) {
		if (src_addr[1] & (IPV6_ADDR_SCOPE_LINKLOCAL|IPV6_ADDR_SCOPE_NODELOCAL))
			return true;
	}

	if ((src_addr[0] & htonl(0xFFC00000)) == htonl(0xFE800000))
		return true;

	return false;
}

static int do_dump_one_inet_fd(int lfd, u32 id, const struct fd_parms *p, int family)
{
	struct inet_sk_desc *sk;
	InetSkEntry ie = INET_SK_ENTRY__INIT;
	IpOptsEntry ipopts = IP_OPTS_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	int ret = -1, err = -1, proto;

	ret = do_dump_opt(lfd, SOL_SOCKET, SO_PROTOCOL,
					&proto, sizeof(proto));
	if (ret)
		goto err;

	if (!can_dump_ipproto(p->stat.st_ino, proto))
		goto err;

	sk = (struct inet_sk_desc *)lookup_socket(p->stat.st_ino, family, proto);
	if (IS_ERR(sk))
		goto err;
	if (!sk) {
		sk = gen_uncon_sk(lfd, p, proto);
		if (!sk)
			goto err;
	}

	if (!can_dump_inet_sk(sk))
		goto err;

	BUG_ON(sk->sd.already_dumped);

	ie.id		= id;
	ie.ino		= sk->sd.ino;
	ie.family	= family;
	ie.proto	= proto;
	ie.type		= sk->type;
	ie.src_port	= sk->src_port;
	ie.dst_port	= sk->dst_port;
	ie.backlog	= sk->wqlen;
	ie.flags	= p->flags;

	ie.fown		= (FownEntry *)&p->fown;
	ie.opts		= &skopts;
	ie.ip_opts	= &ipopts;

	ie.n_src_addr = PB_ALEN_INET;
	ie.n_dst_addr = PB_ALEN_INET;
	if (ie.family == AF_INET6) {
		int val;
		char device[IFNAMSIZ];
		socklen_t len = sizeof(device);

		ie.n_src_addr = PB_ALEN_INET6;
		ie.n_dst_addr = PB_ALEN_INET6;

		ret = dump_opt(lfd, SOL_IPV6, IPV6_V6ONLY, &val);
		if (ret < 0)
			goto err;

		ie.v6only = val ? true : false;
		ie.has_v6only = true;

		/* ifindex only matters on source ports for bind, so let's
		 * find only that ifindex. */
		if (sk->src_port && needs_scope_id(sk->src_addr)) {
			if (getsockopt(lfd, SOL_SOCKET, SO_BINDTODEVICE, device, &len) < 0) {
				pr_perror("can't get ifname");
				goto err;
			}

			if (len > 0) {
				ie.ifname = xstrdup(device);
				if (!ie.ifname)
					goto err;
			} else {
				pr_err("couldn't find ifname for %d, can't bind\n", id);
				goto err;
			}
		}
	}

	ie.src_addr = xmalloc(pb_repeated_size(&ie, src_addr));
	ie.dst_addr = xmalloc(pb_repeated_size(&ie, dst_addr));

	if (!ie.src_addr || !ie.dst_addr)
		goto err;

	memcpy(ie.src_addr, sk->src_addr, pb_repeated_size(&ie, src_addr));
	memcpy(ie.dst_addr, sk->dst_addr, pb_repeated_size(&ie, dst_addr));

	if (dump_ip_opts(lfd, &ipopts))
		goto err;

	if (dump_socket_opts(lfd, &skopts))
		goto err;

	pr_info("Dumping inet socket at %d\n", p->fd);
	show_one_inet("Dumping", sk);
	show_one_inet_img("Dumped", &ie);
	sk->sd.already_dumped = 1;
	sk->cpt_reuseaddr = skopts.reuseaddr;

	switch (proto) {
	case IPPROTO_TCP:
		err = dump_one_tcp(lfd, sk);
		break;
	default:
		err = 0;
		break;
	}

	ie.state = sk->state;

	if (pb_write_one(img_from_set(glob_imgset, CR_FD_INETSK), &ie, PB_INET_SK))
		goto err;
err:
	release_skopts(&skopts);
	xfree(ie.src_addr);
	xfree(ie.dst_addr);
	return err;
}

static int dump_one_inet_fd(int lfd, u32 id, const struct fd_parms *p)
{
	return do_dump_one_inet_fd(lfd, id, p, PF_INET);
}

const struct fdtype_ops inet_dump_ops = {
	.type		= FD_TYPES__INETSK,
	.dump		= dump_one_inet_fd,
};

static int dump_one_inet6_fd(int lfd, u32 id, const struct fd_parms *p)
{
	return do_dump_one_inet_fd(lfd, id, p, PF_INET6);
}

const struct fdtype_ops inet6_dump_ops = {
	.type		= FD_TYPES__INETSK,
	.dump		= dump_one_inet6_fd,
};

int inet_collect_one(struct nlmsghdr *h, int family, int type)
{
	struct inet_sk_desc *d;
	struct inet_diag_msg *m = NLMSG_DATA(h);
	struct nlattr *tb[INET_DIAG_MAX+1];
	int ret;

	nlmsg_parse(h, sizeof(struct inet_diag_msg), tb, INET_DIAG_MAX, NULL);

	d = xzalloc(sizeof(*d));
	if (!d)
		return -1;

	d->type = type;
	d->src_port = ntohs(m->id.idiag_sport);
	d->dst_port = ntohs(m->id.idiag_dport);
	d->state = m->idiag_state;
	d->rqlen = m->idiag_rqueue;
	d->wqlen = m->idiag_wqueue;
	memcpy(d->src_addr, m->id.idiag_src, sizeof(u32) * 4);
	memcpy(d->dst_addr, m->id.idiag_dst, sizeof(u32) * 4);

	if (tb[INET_DIAG_SHUTDOWN])
		d->shutdown = nla_get_u8(tb[INET_DIAG_SHUTDOWN]);
	else
		pr_err_once("Can't check shutdown state of inet socket\n");

	ret = sk_collect_one(m->idiag_inode, family, &d->sd);

	show_one_inet("Collected", d);

	return ret;
}

static int open_inet_sk(struct file_desc *d, int *new_fd);
static int post_open_inet_sk(struct file_desc *d, int sk);

static struct file_desc_ops inet_desc_ops = {
	.type = FD_TYPES__INETSK,
	.open = open_inet_sk,
};

static inline int tcp_connection(InetSkEntry *ie)
{
	return (ie->proto == IPPROTO_TCP && ie->dst_port);
}

static int collect_one_inetsk(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct inet_sk_info *ii = o;

	ii->ie = pb_msg(base, InetSkEntry);
	if (tcp_connection(ii->ie))
		tcp_locked_conn_add(ii);

	/*
	 * A socket can reuse addr only if all previous sockets allow that,
	 * so a value of SO_REUSEADDR can be restored after restoring all
	 * sockets.
	 */
	ii->port = port_add(ii, ii->ie->src_port);
	if (ii->port == NULL)
		return -1;

	return file_desc_add(&ii->d, ii->ie->id, &inet_desc_ops);
}

struct collect_image_info inet_sk_cinfo = {
	.fd_type = CR_FD_INETSK,
	.pb_type = PB_INET_SK,
	.priv_size = sizeof(struct inet_sk_info),
	.collect = collect_one_inetsk,
};

int collect_inet_sockets(void)
{
	return collect_image(&inet_sk_cinfo);
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

static void dec_users_and_wake(struct inet_port *port)
{
	struct fdinfo_list_entry *fle;
	struct inet_sk_info *ii;

	if (atomic_dec_return(&port->users))
		return;
	list_for_each_entry(ii, &port->type_list, port_list) {
		fle = file_master(&ii->d);
		set_fds_event(fle->pid);
	}
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
	if (tcp_connection(ii->ie)) {
		pr_debug("Schedule %d socket for repair off\n", sk);
		BUG_ON(ii->sk_fd != -1);
		ii->sk_fd = sk;
		return 0;
	}

	/* SO_REUSEADDR is set for all sockets */
	if (ii->ie->opts->reuseaddr)
		return 0;

	if (atomic_read(&ii->port->users))
		return 1;

	val = ii->ie->opts->reuseaddr;
	if (restore_opt(sk, SOL_SOCKET, SO_REUSEADDR, &val))
		return -1;

	return 0;
}

int restore_ip_opts(int sk, IpOptsEntry *ioe)
{
	int ret = 0;

	if (ioe->has_freebind)
		ret |= restore_opt(sk, SOL_IP, IP_FREEBIND, &ioe->freebind);

	return ret;
}
static int open_inet_sk(struct file_desc *d, int *new_fd)
{
	struct fdinfo_list_entry *fle = file_master(d);
	struct inet_sk_info *ii;
	InetSkEntry *ie;
	int sk, yes = 1;

	if (fle->stage >= FLE_OPEN)
		return post_open_inet_sk(d, fle->fe->fd);

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
		pr_perror("Can't create inet socket");
		return -1;
	}

	if (ie->v6only) {
		if (restore_opt(sk, SOL_IPV6, IPV6_V6ONLY, &yes) == -1)
			goto err;
	}

	/*
	 * Set SO_REUSEADDR, because some sockets can be bound to one addr.
	 * The origin value of SO_REUSEADDR will be restored in post_open.
	 */
	if (restore_opt(sk, SOL_SOCKET, SO_REUSEADDR, &yes))
		goto err;

	if (tcp_connection(ie)) {
		if (!opts.tcp_established_ok) {
			pr_err("Connected TCP socket in image\n");
			goto err;
		}

		mutex_lock(&ii->port->reuseaddr_lock);
		if (restore_one_tcp(sk, ii)) {
			mutex_unlock(&ii->port->reuseaddr_lock);
			goto err;
		}
		mutex_unlock(&ii->port->reuseaddr_lock);

		goto done;
	}

	if (ie->src_port) {
		if (inet_bind(sk, ii))
			goto err;
	}

	/*
	 * Listen sockets are easiest ones -- simply
	 * bind() and listen(), and that's all.
	 */
	if (ie->state == TCP_LISTEN) {
		if (ie->proto != IPPROTO_TCP) {
			pr_err("Wrong socket in listen state %d\n", ie->proto);
			goto err;
		}

		mutex_lock(&ii->port->reuseaddr_lock);
		if (listen(sk, ie->backlog) == -1) {
			pr_perror("Can't listen on a socket");
			mutex_unlock(&ii->port->reuseaddr_lock);
			goto err;
		}
		mutex_unlock(&ii->port->reuseaddr_lock);
	}

	if (ie->dst_port &&
			inet_connect(sk, ii))
		goto err;
done:
	dec_users_and_wake(ii->port);

	if (rst_file_params(sk, ie->fown, ie->flags))
		goto err;

	if (ie->ip_opts && restore_ip_opts(sk, ie->ip_opts))
		goto err;

	if (restore_socket_opts(sk, ie->opts))
		goto err;

	*new_fd = sk;
	return 1;
err:
	close(sk);
	return -1;
}

int restore_sockaddr(union libsoccr_addr *sa,
		int family, u32 pb_port, u32 *pb_addr, u32 ifindex)
{
	BUILD_BUG_ON(sizeof(sa->v4.sin_addr.s_addr) > PB_ALEN_INET * sizeof(u32));
	BUILD_BUG_ON(sizeof(sa->v6.sin6_addr.s6_addr) > PB_ALEN_INET6 * sizeof(u32));

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

		/* Here although the struct member is called scope_id, the
		 * kernel really wants ifindex. See
		 * /net/ipv6/af_inet6.c:inet6_bind for details.
		 */
		sa->v6.sin6_scope_id = ifindex;
		return sizeof(sa->v6);
	}

	BUG();
	return -1;
}

int inet_bind(int sk, struct inet_sk_info *ii)
{
	bool rst_freebind = false;
	union libsoccr_addr addr;
	int addr_size, ifindex = 0;

	if (ii->ie->ifname) {
		ifindex = if_nametoindex(ii->ie->ifname);
		if (!ifindex) {
			pr_err("couldn't find ifindex for %s\n", ii->ie->ifname);
			return -1;
		}
	}

	addr_size = restore_sockaddr(&addr, ii->ie->family,
			ii->ie->src_port, ii->ie->src_addr, ifindex);

	/*
	 * ipv6 addresses go through a “tentative” phase and
	 * sockets could not be bound to them in this moment
	 * without setting IP_FREEBIND.
	 */
	if (ii->ie->family == AF_INET6) {
		int yes = 1;

		if (restore_opt(sk, SOL_IP, IP_FREEBIND, &yes))
			return -1;

		if (ii->ie->ip_opts && ii->ie->ip_opts->freebind)
			/*
			 * The right value is already set, so
			 * don't need to restore it in restore_ip_opts()
			 */
			ii->ie->ip_opts->has_freebind = false;
		else
			rst_freebind = true;
	}

	if (bind(sk, (struct sockaddr *)&addr, addr_size) == -1) {
		pr_perror("Can't bind inet socket (id %d)", ii->ie->id);
		return -1;
	}

	if (rst_freebind) {
		int no = 0;

		/*
		 * The "no" value is default, so it will not be
		 * restore in restore_ip_opts()
		 */
		if (restore_opt(sk, SOL_IP, IP_FREEBIND, &no))
			return -1;
	}

	return 0;
}

int inet_connect(int sk, struct inet_sk_info *ii)
{
	union libsoccr_addr addr;
	int addr_size;

	addr_size = restore_sockaddr(&addr, ii->ie->family,
			ii->ie->dst_port, ii->ie->dst_addr, 0);

	if (connect(sk, (struct sockaddr *)&addr, addr_size) == -1) {
		pr_perror("Can't connect inet socket back");
		return -1;
	}

	return 0;
}
