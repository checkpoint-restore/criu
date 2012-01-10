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

#include "types.h"
#include "libnetlink.h"
#include "sockets.h"
#include "unix_diag.h"
#include "image.h"
#include "crtools.h"
#include "util.h"

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

#define SK_HASH_SIZE	32
static struct socket_desc *sockets[SK_HASH_SIZE];

static struct socket_desc *lookup_socket(int ino)
{
	struct socket_desc *d;

	for (d = sockets[ino % SK_HASH_SIZE]; d; d = d->next) {
		if (d->ino == ino)
			break;
	}

	return d;
}

static int sk_collect_one(int ino, int family, struct socket_desc *d)
{
	d->ino		= ino;
	d->family	= family;
	d->next		= sockets[ino % SK_HASH_SIZE];

	sockets[ino % SK_HASH_SIZE] = d;

	return 0;
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

static int dump_one_unix(struct socket_desc *_sk, char *fd, struct cr_fdset *cr_fdset)
{
	struct unix_sk_desc *sk = (struct unix_sk_desc *)_sk;
	struct unix_sk_entry ue;

	if (!can_dump_unix_sk(sk))
		goto err;

	ue.fd		= atoi(fd);
	ue.id		= sk->sd.ino;
	ue.type		= sk->type;
	ue.state	= sk->state;
	ue.namelen	= sk->namelen;
	ue.backlog	= sk->wqlen;

	ue.pad		= 0;
	ue.peer		= sk->peer_ino;

	write_ptr_safe(cr_fdset->desc[CR_FD_UNIXSK].fd, &ue, err);
	write_safe(cr_fdset->desc[CR_FD_UNIXSK].fd, sk->name, ue.namelen, err);

	pr_info("Dumping unix socket at %s\n", fd);
	show_one_unix("Dumping", sk);
	show_one_unix_img("Dumped", &ue);

	return 0;

err:
	return -1;
}

int try_dump_socket(char *dir, char *fd, struct cr_fdset *cr_fdset)
{
	struct socket_desc *sk;
	struct statfs fst;
	struct stat st;

	snprintf(buf, sizeof(buf), "%s/%s", dir, fd);
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
	default:
		pr_err("BUG! Unknown socket collected\n");
		return -1;
	}
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
				pr_err("Relative bind path unsupported\n");
				goto err;
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

static int collect_unix_sockets(int nl)
{
	struct msghdr msg;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct {
		struct nlmsghdr hdr;
		struct unix_diag_req r;
	} req;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name	= &nladdr;
	msg.msg_namelen	= sizeof(nladdr);
	msg.msg_iov	= &iov;
	msg.msg_iovlen	= 1;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family= AF_NETLINK;

	iov.iov_base	= &req;
	iov.iov_len	= sizeof(req);

	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_len	= sizeof(req);
	req.hdr.nlmsg_type	= SOCK_DIAG_BY_FAMILY;
	req.hdr.nlmsg_flags	= NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.hdr.nlmsg_seq	= CR_NLMSG_SEQ;
	req.r.sdiag_family	= AF_UNIX;
	req.r.udiag_states	= -1; /* All */
	req.r.udiag_show	= UDIAG_SHOW_NAME | UDIAG_SHOW_VFS | UDIAG_SHOW_PEER |
				  UDIAG_SHOW_ICONS | UDIAG_SHOW_RQLEN;

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

		err = nlmsg_receive(buf, err, unix_receive_one);
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

	nl = socket(PF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
	if (nl < 0) {
		pr_err("Can't create sock diag socket\n");
		return -1;
	}

	err = collect_unix_sockets(nl);
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

		if (reopen_fd_as(aj->fd, fd))
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

static int open_unix_sk_dgram(int sk, struct unix_sk_entry *ue, int *img_fd)
{
	return -1;
}

static int open_unix_sk_stream(int sk, struct unix_sk_entry *ue, int *img_fd)
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

		ret = read(*img_fd, &addr.sun_path, ue->namelen);
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
		if (open_unix_sk_stream(sk, ue, img_fd))
			goto err;
		break;
	case SOCK_DGRAM:
		if (open_unix_sk_dgram(sk, ue, img_fd))
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

		ret = read(usk_fd, &ue, sizeof(ue));
		if (ret == 0)
			break;

		if (ret != sizeof(ue)) {
			pr_perror("%d: Bad unix sk entry (ret %d)\n", pid, ret);
			ret = -1;
			break;
		}

		ret = open_unix_sk(&ue, &usk_fd);
		if (ret)
			break;
	}

	close(usk_fd);

	if (!ret)
		ret = run_connect_jobs();
	if (!ret)
		ret = run_accept_jobs();

err:
	return ret;
}

int prepare_sockets(int pid)
{
	return prepare_unix_sockets(pid);
}

void show_unixsk(char *name, int fd, bool show_header)
{
	struct unix_sk_entry ue;
	int ret = 0;

	if (show_header) {
		pr_info("\n");
		pr_info("CR_FD_UNIXSK: %s\n", name);
		pr_info("----------------------------------------\n");
	}

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
			pr_info("\t---> [%s]\n", buf);
		} else
			pr_info("\n");
	}

out:
	if (ret)
		pr_info("\n");
	if (show_header)
		pr_info("----------------------------------------\n");
}

