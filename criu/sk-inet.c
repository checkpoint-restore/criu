#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/udp.h>
#include <libnl3/netlink/msg.h>
#include <net/if.h>
#include <sys/mman.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <poll.h>

#include "../soccr/soccr.h"

#include "libnetlink.h"
#include "cr_options.h"
#include "imgset.h"
#include "inet_diag.h"
#include "files.h"
#include "image.h"
#include "log.h"
#include "lsm.h"
#include "kerndat.h"
#include "pstree.h"
#include "rst-malloc.h"
#include "sockets.h"
#include "sk-inet.h"
#include "protobuf.h"
#include "util.h"
#include "namespaces.h"

#include "images/inventory.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "inet: "

#define PB_ALEN_INET  1
#define PB_ALEN_INET6 4

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

	if (inet_ntop(sk->sd.family, (void *)sk->src_addr, src_addr, INET_ADDR_LEN) == NULL) {
		pr_perror("Failed to translate address");
	}

	pr_debug("\t%s: ino %#8x family %-10s type %-14s port %8d "
		 "state %-16s src_addr %s\n",
		 act, sk->sd.ino, ___socket_family_name(sk->sd.family), ___socket_type_name(sk->type), sk->src_port,
		 ___tcp_state_name(sk->state), src_addr);
}

static void show_one_inet_img(const char *act, const InetSkEntry *e)
{
	char src_addr[INET_ADDR_LEN] = "<unknown>";

	if (inet_ntop(e->family, (void *)e->src_addr, src_addr, INET_ADDR_LEN) == NULL) {
		pr_perror("Failed to translate address");
	}

	pr_debug("\t%s: family %-10s type %-14s proto %-16s port %d "
		 "state %-16s src_addr %s\n",
		 act, ___socket_family_name(e->family), ___socket_type_name(e->type), ___socket_proto_name(e->proto),
		 e->src_port, ___tcp_state_name(e->state), src_addr);
}

static int can_dump_ipproto(unsigned int ino, int proto, int type)
{
	/* Raw sockets may have any protocol inside */
	if (type == SOCK_RAW)
		return 1;

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
		if (sk->wqlen != 0) {
			if (sk->cork) {
				pr_err("Can't dump corked dgram socket %x\n", sk->sd.ino);
				return 0;
			} else {
				pr_warn("Write queue of the %x socket isn't empty\n", sk->sd.ino);
			}
		}

		if (sk->rqlen)
			pr_warn("Read queue is dropped for socket %x\n", sk->sd.ino);

		return 1;
	}

	if (sk->type != SOCK_STREAM && sk->type != SOCK_RAW) {
		pr_err("Can't dump %d inet socket %x. "
		       "Only stream, dgram and raw are supported.\n",
		       sk->type, sk->sd.ino);
		return 0;
	}

	switch (sk->state) {
	case TCP_LISTEN:
		if (sk->rqlen != 0) {
			if (opts.tcp_skip_in_flight) {
				pr_info("Skipping in-flight connection (l) for %x\n", sk->sd.ino);
				break;
			}
			/*
			 * Currently the ICONS nla reports the conn
			 * requests for listen sockets. Need to pick
			 * those up and fix the connect job respectively
			 */
			pr_err("In-flight connection (l) for %x\n", sk->sd.ino);
			pr_err("In-flight connections can be ignored with the "
			       "--%s option.\n",
			       SK_INFLIGHT_PARAM);
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
		if (!opts.tcp_established_ok && !opts.tcp_close) {
			pr_err("Connected TCP socket, consider using --%s option.\n", SK_EST_PARAM);
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
	}
	if (sa->sa.sa_family == AF_INET6) {
		*pb_port = ntohs(sa->v6.sin6_port);
		memcpy(pb_addr, &sa->v6.sin6_addr, sizeof(sa->v6.sin6_addr));
		return 0;
	}
	return -1;
}

/*
 * There is no direct way to get shutdown state for unconnected sockets,
 * but we can get it indirectly from polling events for a socket.
 */
static int dump_tcp_uncon_shutdown(int lfd, struct inet_sk_desc *sk)
{
	struct pollfd pfd = { .fd = lfd, .events = POLLRDHUP | POLLHUP };

	if (poll(&pfd, 1, 0) != 1) {
		pr_perror("Unable to poll the socket");
		return -1;
	}

	sk->shutdown = 0;

	if ((pfd.revents & POLLHUP) == 0)
		return 0;

	if (pfd.revents & POLLRDHUP)
		sk->shutdown |= SK_SHUTDOWN__READ;

	return 0;
}

static struct inet_sk_desc *gen_uncon_sk(int lfd, const struct fd_parms *p, int proto, int family, int type)
{
	struct inet_sk_desc *sk;
	union libsoccr_addr address;
	struct ns_id *ns = NULL;
	socklen_t aux;
	int ret;

	if (root_ns_mask & CLONE_NEWNET) {
		ns = get_socket_ns(lfd);
		if (ns == NULL)
			return NULL;
	}

	sk = xzalloc(sizeof(*sk));
	if (!sk)
		goto err;

	sk->sd.family = family;
	sk->type = type;

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

	if (type != SOCK_RAW && proto == IPPROTO_TCP) {
		struct {
			__u8 tcpi_state;
			__u8 tcpi_ca_state;
			__u8 tcpi_retransmits;
			__u8 tcpi_probes;
			__u8 tcpi_backoff;
			__u8 tcpi_options;
		} info;

		aux = sizeof(info);
		ret = getsockopt(lfd, SOL_TCP, TCP_INFO, &info, &aux);
		if (ret) {
			pr_perror("Failed to obtain TCP_INFO");
			goto err;
		}

		if (info.tcpi_state != TCP_CLOSE) {
			pr_err("Socket state %d obtained but expected %d\n", info.tcpi_state, TCP_CLOSE);
			goto err;
		}

		sk->wqlen = info.tcpi_backoff;

		if (dump_tcp_uncon_shutdown(lfd, sk))
			goto err;
	}

	sk->state = TCP_CLOSE;

	sk_collect_one(sk->sd.ino, sk->sd.family, &sk->sd, ns);

	return sk;
err:
	xfree(sk);
	return NULL;
}

static int ip_raw_opts_alloc(int family, int proto, IpOptsRawEntry *r)
{
	if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
		if (family == AF_INET6)
			r->n_icmpv_filter = NELEMS_AS_ARRAY(struct icmp6_filter, r->icmpv_filter);
		else
			r->n_icmpv_filter = NELEMS_AS_ARRAY(struct icmp_filter, r->icmpv_filter);
		r->icmpv_filter = xmalloc(pb_repeated_size(r, icmpv_filter));
		pr_debug("r->n_icmpv_filter %d size %d\n", (int)r->n_icmpv_filter,
			 (int)pb_repeated_size(r, icmpv_filter));
		if (!r->icmpv_filter)
			return -ENOMEM;
	}
	return 0;
}

static void ip_raw_opts_free(IpOptsRawEntry *r)
{
	r->n_icmpv_filter = 0;
	xfree(r->icmpv_filter);
	r->icmpv_filter = NULL;
}

static int dump_ip_raw_opts(int sk, int family, int proto, IpOptsRawEntry *r)
{
	int ret = 0;

	ret = ip_raw_opts_alloc(family, proto, r);
	if (ret)
		return ret;

	/*
	 * Either fill icmpv_filter if match or free
	 * so it won't fetch zeros to image.
	 */

	if (family == AF_INET6) {
		ret |= dump_opt(sk, SOL_IPV6, IPV6_HDRINCL, &r->hdrincl);

		if (proto == IPPROTO_ICMPV6)
			ret |= do_dump_opt(sk, SOL_ICMPV6, ICMPV6_FILTER, r->icmpv_filter,
					   pb_repeated_size(r, icmpv_filter));
		else
			ip_raw_opts_free(r);
	} else {
		ret |= dump_opt(sk, SOL_IP, IP_HDRINCL, &r->hdrincl);
		ret |= dump_opt(sk, SOL_IP, IP_NODEFRAG, &r->nodefrag);
		r->has_nodefrag = !!r->nodefrag;

		if (proto == IPPROTO_ICMP)
			ret |= do_dump_opt(sk, SOL_RAW, ICMP_FILTER, r->icmpv_filter,
					   pb_repeated_size(r, icmpv_filter));
		else
			ip_raw_opts_free(r);
	}
	r->has_hdrincl = !!r->hdrincl;

	return ret;
}

static int dump_ip_opts(int sk, int family, int type, int proto, IpOptsEntry *ioe)
{
	int ret = 0;

	if (type == SOCK_RAW) {
		/*
		 * Raw sockets might need allocate more space
		 * and fetch additional options.
		 */
		ret |= dump_ip_raw_opts(sk, family, proto, ioe->raw);
	} else {
		/* Due to kernel code we can use SOL_IP instead of SOL_IPV6 */
		ret |= dump_opt(sk, SOL_IP, IP_FREEBIND, &ioe->freebind);
		ioe->has_freebind = ioe->freebind;
	}

	return ret;
}

/* Stolen from the kernel's __ipv6_addr_type/__ipv6_addr_needs_scopeid;
 * link local and (multicast + loopback + linklocal) addrs require a
 * scope id.
 */
#define IPV6_ADDR_SCOPE_NODELOCAL 0x01
#define IPV6_ADDR_SCOPE_LINKLOCAL 0x02
static bool needs_scope_id(uint32_t *src_addr)
{
	if ((src_addr[0] & htonl(0xFF00000)) == htonl(0xFF000000)) {
		if (src_addr[1] & (IPV6_ADDR_SCOPE_LINKLOCAL | IPV6_ADDR_SCOPE_NODELOCAL))
			return true;
	}

	if ((src_addr[0] & htonl(0xFFC00000)) == htonl(0xFE800000))
		return true;

	return false;
}

static int do_dump_one_inet_fd(int lfd, u32 id, const struct fd_parms *p, int family)
{
	struct inet_sk_desc *sk;
	FileEntry fe = FILE_ENTRY__INIT;
	InetSkEntry ie = INET_SK_ENTRY__INIT;
	IpOptsEntry ipopts = IP_OPTS_ENTRY__INIT;
	IpOptsRawEntry ipopts_raw = IP_OPTS_RAW_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	int ret = -1, err = -1, proto, aux, type;

	ret = do_dump_opt(lfd, SOL_SOCKET, SO_PROTOCOL, &proto, sizeof(proto));
	if (ret)
		goto err;

	if (do_dump_opt(lfd, SOL_SOCKET, SO_TYPE, &type, sizeof(type)))
		goto err;

	if (!can_dump_ipproto(p->stat.st_ino, proto, type))
		goto err;

	if (type == SOCK_RAW)
		sk = (struct inet_sk_desc *)lookup_socket_ino(p->stat.st_ino, family);
	else
		sk = (struct inet_sk_desc *)lookup_socket(p->stat.st_ino, family, proto);
	if (IS_ERR(sk))
		goto err;
	if (!sk) {
		sk = gen_uncon_sk(lfd, p, proto, family, type);
		if (!sk)
			goto err;
	}

	sk->cork = false;
	if (type != SOCK_RAW) {
		switch (proto) {
		case IPPROTO_UDP:
		case IPPROTO_UDPLITE:
			if (dump_opt(lfd, SOL_UDP, UDP_CORK, &aux))
				return -1;
			if (aux) {
				sk->cork = true;
				/*
				 * FIXME: it is possible to dump a corked socket with
				 * the empty send queue.
				 */
				pr_err("Can't dump corked dgram socket %x\n", sk->sd.ino);
				goto err;
			}
			break;
		}
	}

	if (!can_dump_inet_sk(sk))
		goto err;

	BUG_ON(sk->sd.already_dumped);

	ie.id = id;
	ie.ino = sk->sd.ino;
	if (sk->sd.sk_ns) {
		ie.ns_id = sk->sd.sk_ns->id;
		ie.has_ns_id = true;
	}
	ie.family = family;
	ie.proto = proto;
	ie.type = sk->type;
	ie.src_port = sk->src_port;
	ie.dst_port = sk->dst_port;
	ie.backlog = sk->wqlen;
	ie.flags = p->flags;

	ie.fown = (FownEntry *)&p->fown;
	ie.opts = &skopts;
	ie.ip_opts = &ipopts;
	ie.ip_opts->raw = &ipopts_raw;

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

	if (dump_ip_opts(lfd, family, type, proto, &ipopts))
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
		err = (type != SOCK_RAW) ? dump_one_tcp(lfd, sk, &skopts) : 0;
		if (sk->shutdown)
			sk_encode_shutdown(&ie, sk->shutdown);
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		sk_encode_shutdown(&ie, sk->shutdown);
		/* Fallthrough! */
	default:
		err = 0;
		break;
	}

	ie.state = sk->state;

	fe.type = FD_TYPES__INETSK;
	fe.id = ie.id;
	fe.isk = &ie;

	/* Unchain not need field back */
	if (type != SOCK_RAW)
		ie.ip_opts->raw = NULL;

	if (pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE))
		err = -1;
err:
	ip_raw_opts_free(&ipopts_raw);
	release_skopts(&skopts);
	xfree(ie.src_addr);
	xfree(ie.dst_addr);
	xfree(ie.ifname);
	return err;
}

static int dump_one_inet_fd(int lfd, u32 id, const struct fd_parms *p)
{
	return do_dump_one_inet_fd(lfd, id, p, PF_INET);
}

const struct fdtype_ops inet_dump_ops = {
	.type = FD_TYPES__INETSK,
	.dump = dump_one_inet_fd,
};

static int dump_one_inet6_fd(int lfd, u32 id, const struct fd_parms *p)
{
	return do_dump_one_inet_fd(lfd, id, p, PF_INET6);
}

const struct fdtype_ops inet6_dump_ops = {
	.type = FD_TYPES__INETSK,
	.dump = dump_one_inet6_fd,
};

int inet_collect_one(struct nlmsghdr *h, int family, int type, struct ns_id *ns)
{
	struct inet_sk_desc *d;
	struct inet_diag_msg *m = NLMSG_DATA(h);
	struct nlattr *tb[INET_DIAG_MAX + 1];
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

	ret = sk_collect_one(m->idiag_inode, family, &d->sd, ns);

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

static int inet_validate_address(InetSkEntry *ie)
{
	if ((ie->family == AF_INET) &&
	    /* v0.1 had 4 in ipv4 addr len */
	    (ie->n_src_addr >= PB_ALEN_INET) && (ie->n_dst_addr >= PB_ALEN_INET))
		return 0;

	if ((ie->family == AF_INET6) && (ie->n_src_addr == PB_ALEN_INET6) && (ie->n_dst_addr == PB_ALEN_INET6))
		return 0;

	pr_err("Addr len mismatch f %d ss %zu ds %zu\n", ie->family, pb_repeated_size(ie, src_addr),
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
	if (ii->ie->opts->reuseaddr && ii->ie->opts->so_reuseport)
		return 0;

	if (atomic_read(&ii->port->users))
		return 1;

	val = ii->ie->opts->reuseaddr;
	if (!val && restore_opt(sk, SOL_SOCKET, SO_REUSEADDR, &val))
		return -1;

	val = ii->ie->opts->so_reuseport;
	if (!val && restore_opt(sk, SOL_SOCKET, SO_REUSEPORT, &val))
		return -1;

	val = ii->ie->opts->so_broadcast;
	if (!val && restore_opt(sk, SOL_SOCKET, SO_BROADCAST, &val))
		return -1;

	val = ii->ie->opts->so_keepalive;
	if (!val && restore_opt(sk, SOL_SOCKET, SO_KEEPALIVE, &val))
		return -1;

	return 0;
}

static int restore_ip_raw_opts(int sk, int family, int proto, IpOptsRawEntry *r)
{
	int ret = 0;

	if (r->icmpv_filter) {
		if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
			ret |= do_restore_opt(sk, family == AF_INET6 ? SOL_ICMPV6 : SOL_RAW,
					      family == AF_INET6 ? ICMPV6_FILTER : ICMP_FILTER, r->icmpv_filter,
					      pb_repeated_size(r, icmpv_filter));
		}
	}

	if (r->has_nodefrag)
		ret |= restore_opt(sk, SOL_IP, IP_NODEFRAG, &r->nodefrag);
	if (r->has_hdrincl)
		ret |= restore_opt(sk, family == AF_INET6 ? SOL_IPV6 : SOL_IP,
				   family == AF_INET6 ? IPV6_HDRINCL : IP_HDRINCL, &r->hdrincl);

	return ret;
}

int restore_ip_opts(int sk, int family, int proto, IpOptsEntry *ioe)
{
	int ret = 0;

	if (ioe->has_freebind)
		ret |= restore_opt(sk, SOL_IP, IP_FREEBIND, &ioe->freebind);

	if (ioe->raw)
		ret |= restore_ip_raw_opts(sk, family, proto, ioe->raw);
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

	if ((ie->type != SOCK_STREAM) && (ie->type != SOCK_DGRAM) && (ie->type != SOCK_RAW)) {
		pr_err("Unsupported socket type: %d\n", ie->type);
		return -1;
	}

	if (inet_validate_address(ie))
		return -1;

	if (set_netns(ie->ns_id))
		return -1;

	if (run_setsockcreatecon(fle->fe))
		return -1;

	sk = socket(ie->family, ie->type, ie->proto);
	if (sk < 0) {
		pr_perror("Can't create inet socket");
		return -1;
	}

	if (reset_setsockcreatecon())
		goto err;

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
	if (restore_opt(sk, SOL_SOCKET, SO_REUSEPORT, &yes))
		goto err;

	if (tcp_connection(ie)) {
		if (!opts.tcp_established_ok && !opts.tcp_close) {
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

	if (ie->dst_port && inet_connect(sk, ii))
		goto err;
done:
	dec_users_and_wake(ii->port);

	if (rst_file_params(sk, ie->fown, ie->flags))
		goto err;

	if (ie->ip_opts && restore_ip_opts(sk, ie->family, ie->proto, ie->ip_opts))
		goto err;

	if (restore_socket_opts(sk, ie->opts))
		goto err;

	if (ie->has_shutdown &&
	    (ie->proto == IPPROTO_UDP || ie->proto == IPPROTO_UDPLITE || ie->proto == IPPROTO_TCP)) {
		if (shutdown(sk, sk_decode_shutdown(ie->shutdown))) {
			if (ie->state != TCP_CLOSE && errno != ENOTCONN) {
				pr_perror("Can't shutdown socket into %d", sk_decode_shutdown(ie->shutdown));
				goto err;
			} else {
				pr_debug("Called shutdown on closed socket, "
					 "proto %d ino %x",
					 ie->proto, ie->ino);
			}
		}
	}

	*new_fd = sk;

	return 1;
err:
	close(sk);
	return -1;
}

int restore_sockaddr(union libsoccr_addr *sa, int family, u32 pb_port, u32 *pb_addr, u32 ifindex)
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

	addr_size = restore_sockaddr(&addr, ii->ie->family, ii->ie->src_port, ii->ie->src_addr, ifindex);

	/*
	 * ipv6 addresses go through a “tentative” phase and
	 * sockets could not be bound to them in this moment
	 * without setting IP_FREEBIND.
	 */
	if (ii->ie->family == AF_INET6 && ii->ie->type != SOCK_RAW) {
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

	addr_size = restore_sockaddr(&addr, ii->ie->family, ii->ie->dst_port, ii->ie->dst_addr, 0);

	if (connect(sk, (struct sockaddr *)&addr, addr_size) == -1) {
		pr_perror("Can't connect inet socket back");
		return -1;
	}

	return 0;
}
