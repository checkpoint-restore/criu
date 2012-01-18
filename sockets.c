#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <linux/net.h>
#include <linux/un.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>

#include "types.h"
#include "libnetlink.h"
#include "sockets.h"
#include "unix_diag.h"
#include "image.h"
#include "crtools.h"
#include "util.h"
#include "inet_diag.h"

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
	unsigned int		*icons;
};

#define INET_ADDR_LEN		40

struct inet_sk_desc {
	struct socket_desc	sd;
	unsigned int		type;
	unsigned int		proto;
	unsigned int		src_port;
	unsigned int		state;
	unsigned int		rqlen;
	unsigned int		wqlen;
	unsigned int		src_addr[4];
};

#define SK_HASH_SIZE	32
static struct socket_desc *sockets[SK_HASH_SIZE];

#define __gen_static_lookup_func(ret, name, head, _member, _type, _name)\
	static ret *name(_type _name) {					\
		ret *d;							\
		for (d = head[_name % SK_HASH_SIZE]; d; d = d->next) {	\
			if (d->_member == _name)			\
				break;					\
		}							\
		return d;						\
	}

__gen_static_lookup_func(struct socket_desc, lookup_socket, sockets, ino, int, ino);

static int sk_collect_one(int ino, int family, struct socket_desc *d)
{
	d->ino		= ino;
	d->family	= family;
	d->next		= sockets[ino % SK_HASH_SIZE];

	sockets[ino % SK_HASH_SIZE] = d;

	return 0;
}

static void show_one_inet(char *act, struct inet_sk_desc *sk)
{
	char src_addr[INET_ADDR_LEN] = "<unknown>";

	if (inet_ntop(AF_INET, (void *)sk->src_addr, src_addr,
		      INET_ADDR_LEN) == NULL) {
		pr_err("Failed to translate address: %d\n", errno);
	}

	dprintk("\t%s: ino %d family %d type %d port %d "
		"state %d src_addr %s\n",
		act, sk->sd.ino, sk->sd.family, sk->type, sk->src_port,
		sk->state, src_addr);
}

static void show_one_inet_img(char *act, struct inet_sk_entry *e)
{
	char src_addr[INET_ADDR_LEN] = "<unknown>";

	if (inet_ntop(AF_INET, (void *)e->src_addr, src_addr,
		      INET_ADDR_LEN) == NULL) {
		pr_err("Failed to translate address: %d\n", errno);
	}

	dprintk("\t%s: fd %d family %d type %d proto %d port %d "
		"state %d src_addr %d\n",
		act, e->fd, e->family, e->type, e->proto, e->src_port, e->state,
		src_addr);
}

static void show_one_unix(char *act, struct unix_sk_desc *sk)
{
	dprintk("\t%s: ino %d type %d state %d name %s\n",
		act, sk->sd.ino, sk->type, sk->state, sk->name);
}

static void show_one_unix_img(char *act, struct unix_sk_entry *e)
{
	dprintk("\t%s: fd %d type %d state %d name %d bytes\n",
		act, e->fd, e->type, e->state, e->namelen);
}

static int can_dump_inet_sk(struct inet_sk_desc *sk)
{
	if (sk->sd.family != AF_INET) {
		pr_err("Only IPv4 sockets for now\n");
		return 0;
	}

	if (sk->type != SOCK_STREAM) {
		pr_err("Only stream inet sockets for now\n");
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

static int dump_one_inet(struct socket_desc *_sk, int fd, struct cr_fdset *cr_fdset)
{
	struct inet_sk_desc *sk = (struct inet_sk_desc *)_sk;
	struct inet_sk_entry ie;

	if (!can_dump_inet_sk(sk))
		goto err;

	memset(&ie, 0, sizeof(ie));

	ie.fd		= fd;
	ie.id		= sk->sd.ino;
	ie.family	= sk->sd.family;
	ie.type		= sk->type;
	ie.proto	= sk->proto;
	ie.state	= sk->state;
	ie.src_port	= sk->src_port;
	ie.backlog	= sk->wqlen;
	memcpy(ie.src_addr, sk->src_addr, sizeof(u32) * 4);

	write_ptr_safe(cr_fdset->fds[CR_FD_INETSK], &ie, err);

	pr_info("Dumping inet socket at %d\n", fd);
	show_one_inet("Dumping", sk);
	show_one_inet_img("Dumped", &ie);
	return 0;

err:
	return -1;
}

static int can_dump_unix_sk(struct unix_sk_desc *sk)
{
	if (sk->type != SOCK_STREAM &&
	    sk->type != SOCK_DGRAM) {
		pr_err("Only stream/dgram sockets for now\n");
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
		if (!sk->peer_ino) {
			/*
			 * Read above
			 */
			pr_err("In-flight connection\n");
			return 0;
		}

		if (sk->rqlen) {
			/*
			 * The hard case :( Currentl there's no way to
			 * clone the sk queue. Even the MSG_PEEK doesn't
			 * help, since it picks up the head of the queue
			 * always. Some more patches should go
			 */
			pr_err("Non empty queue\n");
			return 0;
		}

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

static int dump_one_unix(struct socket_desc *_sk, int fd, struct cr_fdset *cr_fdset)
{
	struct unix_sk_desc *sk = (struct unix_sk_desc *)_sk;
	struct unix_sk_entry ue;

	if (!can_dump_unix_sk(sk))
		goto err;

	ue.fd		= fd;
	ue.id		= sk->sd.ino;
	ue.type		= sk->type;
	ue.state	= sk->state;
	ue.namelen	= sk->namelen;
	ue.backlog	= sk->wqlen;

	ue.pad		= 0;
	ue.peer		= sk->peer_ino;

	write_ptr_safe(cr_fdset->fds[CR_FD_UNIXSK], &ue, err);
	write_safe(cr_fdset->fds[CR_FD_UNIXSK], sk->name, ue.namelen, err);

	pr_info("Dumping unix socket at %d\n", fd);
	show_one_unix("Dumping", sk);
	show_one_unix_img("Dumped", &ue);

	return 0;

err:
	return -1;
}

int try_dump_socket(pid_t pid, int fd, struct cr_fdset *cr_fdset)
{
	struct socket_desc *sk;
	struct statfs fst;
	struct stat st;
	char path[64];

	/*
	 * Sockets are tricky, we can't open it but can
	 * do stats over and check for sokets magic.
	 */
	snprintf(buf, sizeof(buf), "/proc/%d/fd/%d", pid, fd);
	if (statfs(buf, &fst)) {
		pr_err("Can't statfs %s\n", buf);
		return -1;
	}

	if (stat(buf, &st)) {
		pr_err("Can't stat %s\n", buf);
		return -1;
	}

	if (fst.f_type != SOCKFS_MAGIC)
		return 1; /* not a socket, proceed with caller error */

	sk = lookup_socket(st.st_ino);
	if (!sk) {
		pr_err("Uncollected socket %d\n", st.st_ino);
		return -1;
	}

	switch (sk->family) {
	case AF_UNIX:
		return dump_one_unix(sk, fd, cr_fdset);
	case AF_INET:
		return dump_one_inet(sk, fd, cr_fdset);
	default:
		pr_err("BUG! Unknown socket collected\n");
		break;
	}

	return -1;
}

static int inet_tcp_collect_one(struct inet_diag_msg *m, struct rtattr **tb)
{
	struct inet_sk_desc *d;

	d = xzalloc(sizeof(*d));
	if (!d)
		return -1;

	d->type = SOCK_STREAM;
	d->proto = IPPROTO_TCP;
	d->src_port = ntohs(m->id.idiag_sport);
	d->state = m->idiag_state;
	d->rqlen = m->idiag_rqueue;
	d->wqlen = m->idiag_wqueue;
	memcpy(d->src_addr, m->id.idiag_src, sizeof(u32) * 4);

	return sk_collect_one(m->idiag_inode, AF_INET, &d->sd);
}

static int inet_tcp_receive_one(struct nlmsghdr *h)
{
	struct inet_diag_msg *m = NLMSG_DATA(h);
	struct rtattr *tb[INET_DIAG_MAX+1];

	parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr *)(m + 1),
		     h->nlmsg_len - NLMSG_LENGTH(sizeof(*m)));

	return inet_tcp_collect_one(m, tb);
}

static int unix_collect_one(struct unix_diag_msg *m, struct rtattr **tb)
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

		if (name[0] != '\0' && d->state == TCP_LISTEN) {
			struct unix_diag_vfs *uv;
			struct stat st;

			if (name[0] != '/') {
				pr_warning("Relative bind path unsupported\n");
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
				pr_perror("Can't stat socket %d(%s)\n",
						m->udiag_ino, name);
				goto err;
			}

			if ((st.st_ino != uv->udiag_vfs_ino) ||
			    (st.st_dev == uv->udiag_vfs_dev)) {
				/*
				 * When a listen socket is bound to
				 * unlinked file, we just drop his name,
				 * since noone will access it via one.
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

		d->icons = xmalloc(len + sizeof(u32));
		if (!d->icons)
			goto err;

		memcpy(d->icons, RTA_DATA(tb[UNIX_DIAG_ICONS]), len);
		d->icons[len / sizeof(u32)] = 0;
	}

	if (tb[UNIX_DIAG_RQLEN]) {
		struct unix_diag_rqlen *rq;

		rq = (struct unix_diag_rqlen *)RTA_DATA(tb[UNIX_DIAG_RQLEN]);
		d->rqlen = rq->udiag_rqueue;
		d->wqlen = rq->udiag_wqueue;
	}

	show_one_unix("Collected", d);

	return sk_collect_one(m->udiag_ino, AF_UNIX, &d->sd);

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
		pr_perror("Can't send request message\n");
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
			else
				goto err;
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
	int err;
	int nl;
	int supp_type = 0;
	struct {
		struct nlmsghdr hdr;
		union {
			struct unix_diag_req u;
			struct inet_diag_req i;
		} r;
	} req;

	nl = socket(PF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
	if (nl < 0) {
		pr_err("Can't create sock diag socket\n");
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
	err = collect_sockets_nl(nl, &req, sizeof(req), unix_receive_one);
	if (err)
		goto out;

	/* Collect IPv4 TCP sockets */
	req.r.i.sdiag_family	= AF_INET;
	req.r.i.sdiag_protocol	= IPPROTO_TCP;
	req.r.i.idiag_ext	= 1 << (INET_DIAG_INFO - 1);
	/* Only listening sockets supported yet */
	req.r.i.idiag_states	= 1 << TCP_LISTEN;
	err = collect_sockets_nl(nl, &req, sizeof(req), inet_tcp_receive_one);

out:
	close(nl);
	return err;
}

struct unix_conn_job {
	struct sockaddr_un	addr;
	int			addrlen;
	int			fd;
	struct unix_conn_job	*next;
};

static void unix_show_job(char *type, int fd, int id)
{
	dprintk("%s job fd %d id %d\n", type, fd, id);
}

static struct unix_conn_job *conn_jobs;

static int run_connect_jobs(void)
{
	struct unix_conn_job *cj, *next;

	cj = conn_jobs;
	while (cj) {
		int attempts = 8;

		unix_show_job("Run conn", cj->fd, -1);
try_again:
		if (connect(cj->fd, (struct sockaddr *)&cj->addr, cj->addrlen) < 0) {
			if (attempts) {
				usleep(1000);
				attempts--;
				goto try_again; /* FIXME - use avagin@'s waiters */
			}
			pr_perror("Can't restore connection (c)\n");
			return -1;
		}

		unix_show_job("Fin conn", cj->fd, -1);
		next = cj->next;
		xfree(cj);
		cj = next;
	}

	return 0;
}

struct unix_accept_job {
	int			fd;
	struct unix_accept_job	*next;
};

static struct unix_accept_job *accept_jobs;

static int run_accept_jobs(void)
{
	struct unix_accept_job *aj, *next;

	aj = accept_jobs;
	while (aj) {
		int fd;

		unix_show_job("Run acc", aj->fd, -1);
		fd = accept(aj->fd, NULL, NULL);
		if (fd < 0) {
			pr_perror("Can't restore connection (s)\n");
			return -1;
		}

		if (reopen_fd_as_nocheck(aj->fd, fd))
			return -1;

		unix_show_job("Fin acc", aj->fd, -1);
		next = aj->next;
		xfree(aj);
		aj = next;
	}

	return 0;
}

static void prep_conn_addr(int id, struct sockaddr_un *addr, int *addrlen)
{
	addr->sun_family = AF_UNIX;
	addr->sun_path[0] = '\0';

	snprintf(addr->sun_path + 1, UNIX_PATH_MAX - 1, "crtools-sk-%10d", id);

	*addrlen = sizeof(addr->sun_family) + sizeof("crtools-sk-") - 1 + 10;
}

struct unix_dgram_bound {
	struct unix_dgram_bound	*next;
	struct sockaddr_un	addr;
	int			id;
};

struct unix_dgram_peer {
	struct unix_dgram_peer	*next;
	int			fd;
	int			peer;
};

static struct unix_dgram_bound	*dgram_bound[SK_HASH_SIZE];
static struct unix_dgram_peer	*dgram_peer;

__gen_static_lookup_func(struct unix_dgram_bound, lookup_dgram_bound, dgram_bound, id, int, id);

static int run_connect_jobs_dgram(void)
{
	struct unix_dgram_bound	*b;
	struct unix_dgram_peer	*d;
	int i;

	for (d = dgram_peer; d; d = d->next) {
		b = lookup_dgram_bound(d->peer);
		if (!b) {
			pr_err("Unconnected socket for peer %d\n", d->peer);
			goto err;
		}

		if (connect(d->fd, (struct sockaddr *)&b->addr, sizeof(b->addr)) < 0) {
			pr_perror("Can't connect peer %d on fd %d\n",
				  d->peer, d->fd);
			goto err;
		}
	}

	/*
	 * Free data we don't need anymore.
	 */
	for (d = dgram_peer; d;) {
		d = d->next;
		xfree(d);
	}

	for (i = 0; i < SK_HASH_SIZE; i++) {
		if (!dgram_bound[i])
			continue;
		for (b = dgram_bound[i]; b;) {
			b = b->next;
			xfree(b);
		}
	}

	return 0;
err:
	return -1;
}

static int open_unix_sk_dgram(int sk, struct unix_sk_entry *ue, int img_fd)
{
	if (ue->namelen) {

		/*
		 * This is trivial socket bind() case,
		 * we don't have to wait for connect().
		 */

		struct unix_dgram_bound *d;
		struct sockaddr_un addr;
		int ret;

		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;

		ret = read(img_fd, &addr.sun_path, ue->namelen);
		if (ret != ue->namelen) {
			pr_err("Error reading socket name from image (%d)", ret);
			goto err;
		}

		if (addr.sun_path[0] != '\0')
			unlink(addr.sun_path);
		if (bind(sk, (struct sockaddr *)&addr,
			 sizeof(addr.sun_family) + ue->namelen) < 0) {
			pr_perror("Can't bind socket\n");
			goto err;
		}

		/*
		 * Just remember it and connect() if needed.
		 */
		d = xmalloc(sizeof(*d));
		if (!d)
			goto err;

		memcpy(&d->addr, &addr, sizeof(d->addr));
		d->id	= ue->id;

		d->next = dgram_bound[d->id % SK_HASH_SIZE];
		dgram_bound[d->id % SK_HASH_SIZE] = d;
	}

	if (ue->peer) {

		/*
		 * Connected sockets are a bit compound,
		 * we might need to defer connect() call
		 * until peer is alive.
		 */

		struct unix_dgram_peer *d;

		d = xmalloc(sizeof(*d));
		if (!d)
			goto err;

		d->peer	= ue->peer;
		d->fd	= ue->fd;
		d->next = dgram_peer;

		dgram_peer = d;
	}

	return 0;
err:
	return -1;
}

static int open_unix_sk_stream(int sk, struct unix_sk_entry *ue, int img_fd)
{
	int ret = -1;

	if (ue->state == TCP_LISTEN) {
		struct sockaddr_un addr;
		int ret;

		/*
		 * Listen sockets are easiest ones -- simply
		 * bind() and listen(), and that's all.
		 */
		if (!ue->namelen || ue->namelen >= UNIX_PATH_MAX) {
			pr_err("Bad unix name len %d\n", ue->namelen);
			goto err;
		}

		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;

		ret = read(img_fd, &addr.sun_path, ue->namelen);
		if (ret != ue->namelen) {
			pr_err("Error reading socket name from image (%d)", ret);
			goto err;
		}

		if (addr.sun_path[0] != '\0')
			unlink(addr.sun_path);
		if (bind(sk, (struct sockaddr *)&addr,
			 sizeof(addr.sun_family) + ue->namelen) < 0) {
			pr_perror("Can't bind socket\n");
			goto err;
		}

		if (listen(sk, ue->backlog) < 0) {
			pr_perror("Can't listen socket\n");
			goto err;
		}
	} else if (ue->state == TCP_ESTABLISHED) {

		/*
		 * If a connection is established we need
		 * two separate steps -- one peer become
		 * a server and do bind()/listen(), then
		 * it deferred to accept() later, while
		 * another peer become a client and
		 * deferred to connect() later.
		 */

		if (ue->peer < ue->id) {
			struct sockaddr_un addr;
			int len;
			struct unix_accept_job *aj;

			/*
			 * Will become a server
			 */

			prep_conn_addr(ue->id, &addr, &len);
			if (bind(sk, (struct sockaddr *)&addr, len) < 0) {
				pr_perror("Can't bind socket\n");
				goto err;
			}

			if (listen(sk, 1) < 0) {
				pr_perror("Can't listen socket\n");
				goto err;
			}

			aj = xmalloc(sizeof(*aj));
			if (aj == NULL)
				goto err;

			aj->fd = ue->fd;
			aj->next = accept_jobs;
			accept_jobs = aj;
			unix_show_job("Sched acc", ue->fd, ue->id);
		} else {
			struct unix_conn_job *cj;

			/*
			 * Will do the connect
			 */

			cj = xmalloc(sizeof(*cj));
			if (!cj)
				goto err;

			prep_conn_addr(ue->peer, &cj->addr, &cj->addrlen);
			cj->fd = ue->fd;
			cj->next = conn_jobs;
			conn_jobs = cj;
			unix_show_job("Sched conn", ue->fd, ue->peer);
		}
	} else {
		pr_err("Unknown state %d\n", ue->state);
		goto err;
	}

	ret = 0;
err:
	return ret;
}

static int open_unix_sk(struct unix_sk_entry *ue, int *img_fd)
{
	int sk;

	show_one_unix_img("Restore", ue);

	sk = socket(PF_UNIX, ue->type, 0);
	if (sk < 0) {
		pr_perror("Can't create unix socket\n");
		return -1;
	}

	switch (ue->type) {
	case SOCK_STREAM:
		if (open_unix_sk_stream(sk, ue, *img_fd))
			goto err;
		break;
	case SOCK_DGRAM:
		if (open_unix_sk_dgram(sk, ue, *img_fd))
			goto err;
		break;
	default:
		pr_err("Unsupported socket type: %d\n", ue->type);
		goto err;
	}

	if (move_img_fd(img_fd, ue->fd))
		return -1;

	return reopen_fd_as(ue->fd, sk);

err:
	close(sk);
	return -1;
}

static int prepare_unix_sockets(int pid)
{
	int usk_fd, ret = -1;

	usk_fd = open_image_ro(CR_FD_UNIXSK, pid);
	if (usk_fd < 0)
		return -1;

	while (1) {
		struct unix_sk_entry ue;

		ret = read_ptr_safe_eof(usk_fd, &ue, err);
		if (ret == 0)
			break;

		ret = open_unix_sk(&ue, &usk_fd);
		if (ret)
			break;
	}
err:
	close(usk_fd);

	if (!ret)
		ret = run_connect_jobs_dgram();
	if (!ret)
		ret = run_connect_jobs();
	if (!ret)
		ret = run_accept_jobs();

	return ret;
}

static int open_inet_sk(struct inet_sk_entry *ie, int *img_fd)
{
	int sk;
	struct sockaddr_in addr;

	show_one_inet_img("Restore", ie);

	if (ie->family != AF_INET) {
		pr_err("Unsupported socket family: %d\n", ie->family);
		goto err;
	}

	if (ie->type != SOCK_STREAM) {
		pr_err("Unsupported socket type: %d\n", ie->type);
		goto err;
	}

	sk = socket(ie->family, ie->type, ie->proto);
	if (sk < 0) {
		pr_perror("Can't create unix socket\n");
		return -1;
	}

	/*
	 * Listen sockets are easiest ones -- simply
	 * bind() and listen(), and that's all.
	 */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = ie->family;
	addr.sin_port = htons(ie->src_port);
	memcpy(&addr.sin_addr.s_addr, ie->src_addr, sizeof(unsigned int) * 4);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		pr_err("Inet socket bind failed");
		goto err;
	}

	if (listen(sk, ie->backlog) == -1) {
		pr_err ("listen() failed %m");
		goto err;
	}

	if (move_img_fd(img_fd, ie->fd))
		return -1;

	return reopen_fd_as(ie->fd, sk);

err:
	close(sk);
	return -1;
}

static int prepare_inet_sockets(int pid)
{
	int isk_fd, ret = -1;

	isk_fd = open_image_ro(CR_FD_INETSK, pid);
	if (isk_fd < 0)
		return -1;

	while (1) {
		struct inet_sk_entry ie;

		ret = read_ptr_safe_eof(isk_fd, &ie, err);
		if (ret == 0)
			break;

		ret = open_inet_sk(&ie, &isk_fd);
		if (ret)
			break;
	}
err:
	close(isk_fd);
	return ret;
}

int prepare_sockets(int pid)
{
	int err;

	pr_info("%d: Opening sockets\n", pid);
	err = prepare_unix_sockets(pid);
	if (err)
		return err;
	return prepare_inet_sockets(pid);
}

void show_inetsk(int fd)
{
	struct inet_sk_entry ie;
	int ret = 0;

	pr_img_head(CR_FD_INETSK);

	while (1) {
		char src_addr[INET_ADDR_LEN] = "<unknown>";

		ret = read_ptr_safe_eof(fd, &ie, out);
		if (!ret)
			goto out;

		if (inet_ntop(AF_INET, (void *)ie.src_addr, src_addr,
			      INET_ADDR_LEN) == NULL) {
			pr_err("Failed to translate address: %d\n", errno);
		}

		pr_info("fd %d family %d type %d proto %d port %d state %d "
			"--> %s\n", ie.fd, ie.family, ie.type, ie.proto,
			ie.src_port, ie.state, src_addr);
	}

out:
	if (ret)
		pr_info("\n");
	pr_img_tail(CR_FD_INETSK);
}

void show_unixsk(int fd)
{
	struct unix_sk_entry ue;
	int ret = 0;

	pr_img_head(CR_FD_UNIXSK);

	while (1) {
		ret = read_ptr_safe_eof(fd, &ue, out);
		if (!ret)
			goto out;

		pr_info("fd %4d type %2d state %2d namelen %4d backlog %4d id %6d peer %6d",
			ue.fd, ue.type, ue.state, ue.namelen, ue.namelen, ue.id, ue.peer);

		if (ue.namelen) {
			ret = read_safe_eof(fd, buf, ue.namelen, out);
			if (!ret)
				goto out;
			if (!buf[0])
				buf[0] = '@';
			pr_info(" --> %s\n", buf);
		} else
			pr_info("\n");
	}

out:
	if (ret)
		pr_info("\n");
	pr_img_tail(CR_FD_UNIXSK);
}

