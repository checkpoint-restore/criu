#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/un.h>
#include <stdlib.h>

#include "types.h"
#include "libnetlink.h"
#include "crtools.h"
#include "unix_diag.h"
#include "files.h"
#include "file-ids.h"
#include "image.h"
#include "log.h"
#include "util.h"
#include "util-net.h"
#include "sockets.h"
#include "sk-queue.h"

static char buf[4096];

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
	struct list_head	list;
};

static LIST_HEAD(unix_sockets);

struct unix_sk_listen_icon {
	unsigned int			peer_ino;
	struct unix_sk_desc		*sk_desc;
	struct unix_sk_listen_icon	*next;
};

#define SK_HASH_SIZE		32

static struct unix_sk_listen_icon *unix_listen_icons[SK_HASH_SIZE];

static struct unix_sk_listen_icon *lookup_unix_listen_icons(int peer_ino)
{
	struct unix_sk_listen_icon *ic;

	for (ic = unix_listen_icons[peer_ino % SK_HASH_SIZE];
			ic; ic = ic->next)
		if (ic->peer_ino == peer_ino)
			return ic;
	return NULL;
}

static void show_one_unix(char *act, const struct unix_sk_desc *sk)
{
	pr_debug("\t%s: ino 0x%x peer_ino 0x%x family %4d type %4d state %2d name %s\n",
		act, sk->sd.ino, sk->peer_ino, sk->sd.family, sk->type, sk->state, sk->name);

	if (sk->nr_icons) {
		int i;

		for (i = 0; i < sk->nr_icons; i++)
			pr_debug("\t\ticon: %4d\n", sk->icons[i]);
	}
}

static void show_one_unix_img(const char *act, const struct unix_sk_entry *e)
{
	pr_info("\t%s: id 0x%x ino 0x%x peer 0x%x type %d state %d name %d bytes\n",
		act, e->id, e->ino, e->peer, e->type, e->state, e->namelen);
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
		if (sk->type != SOCK_DGRAM) {
			pr_err("Unexpected state %d on type %d\n",
				sk->state, sk->type);
			return 0;
		}
		break;
	default:
		pr_err("Unknown state %d\n", sk->state);
		return 0;
	}

	return 1;
}

static int dump_one_unix_fd(int lfd, u32 id, const struct fd_parms *p)
{
	struct unix_sk_desc *sk;
	struct unix_sk_entry ue;

	sk = (struct unix_sk_desc *)lookup_socket(p->stat.st_ino);
	if (!sk)
		goto err;

	if (!can_dump_unix_sk(sk))
		goto err;

	BUG_ON(sk->sd.already_dumped);

	ue.id		= id;
	ue.ino		= sk->sd.ino;
	ue.type		= sk->type;
	ue.state	= sk->state;
	ue.namelen	= sk->namelen;
	ue.flags	= p->flags;
	ue.backlog	= sk->wqlen;
	ue.peer		= sk->peer_ino;
	ue.fown		= p->fown;
	ue.uflags	= 0;

	if (ue.peer) {
		struct unix_sk_desc *peer;

		peer = (struct unix_sk_desc *)lookup_socket(ue.peer);
		if (!peer) {
			pr_err("Unix socket %#x without peer %#x\n",
					ue.ino, ue.peer);
			goto err;
		}

		/*
		 * Peer should have us as peer or have a name by which
		 * we can access one.
		 */
		if (peer->peer_ino != ue.ino) {
			if (!peer->name) {
				pr_err("Unix socket %#x with unreachable peer %#x (%#x/%s)\n",
				       ue.ino, ue.peer, peer->peer_ino, peer->name);
				goto err;
			}

			/*
			 * It can be external socket, so we defer dumping
			 * until all sockets the program owns are processed.
			 */
			if (!peer->sd.already_dumped)
				list_add_tail(&peer->list, &unix_sockets);
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

		e = lookup_unix_listen_icons(ue.ino);
		if (!e) {
			pr_err("Dangling in-flight connection %d\n", ue.ino);
			goto err;
		}

		/* e->sk_desc is _never_ NULL */
		if (e->sk_desc->state != TCP_LISTEN) {
			pr_err("In-flight connection on "
				"non-listening socket %d\n", ue.ino);
			goto err;
		}

		ue.peer = e->sk_desc->sd.ino;

		pr_debug("\t\tFixed inflight socket %#x peer %#x)\n",
				ue.ino, ue.peer);
	}

	if (dump_socket_opts(lfd, &ue.opts))
		goto err;

	if (write_img(fdset_fd(glob_fdset, CR_FD_UNIXSK), &ue))
		goto err;
	if (write_img_buf(fdset_fd(glob_fdset, CR_FD_UNIXSK), sk->name, ue.namelen))
		goto err;

	if (sk->rqlen != 0 && !(sk->type == SOCK_STREAM &&
				sk->state == TCP_LISTEN))
		if (dump_sk_queue(lfd, ue.id))
			goto err;

	pr_info("Dumping unix socket at %d\n", p->fd);
	show_one_unix("Dumping", sk);
	show_one_unix_img("Dumped", &ue);

	list_del_init(&sk->list);
	sk->sd.already_dumped = 1;
	return 0;

err:
	return -1;
}

static const struct fdtype_ops unix_dump_ops = {
	.type		= FDINFO_UNIXSK,
	.make_gen_id	= make_gen_id,
	.dump		= dump_one_unix_fd,
};

int dump_one_unix(struct fd_parms *p, int lfd, const struct cr_fdset *set)
{
	return do_dump_gen_file(p, lfd, &unix_dump_ops, set);
}

static int unix_collect_one(const struct unix_diag_msg *m,
		struct rtattr **tb)
{
	struct unix_sk_desc *d;

	d = xzalloc(sizeof(*d));
	if (!d)
		return -1;

	d->type	= m->udiag_type;
	d->state= m->udiag_state;
	INIT_LIST_HEAD(&d->list);

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
						"sk %#x.%#x real %#x.%#x\n",
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
			struct unix_sk_listen_icon *e, **chain;
			int n;

			e = xzalloc(sizeof(*e));
			if (!e)
				goto err;

			n = d->icons[i];
			chain = &unix_listen_icons[n % SK_HASH_SIZE];
			e->next = *chain;
			*chain = e;

			pr_debug("\t\tCollected icon %d\n", d->icons[i]);

			e->peer_ino	= n;
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

int unix_receive_one(struct nlmsghdr *h)
{
	struct unix_diag_msg *m = NLMSG_DATA(h);
	struct rtattr *tb[UNIX_DIAG_MAX+1];

	parse_rtattr(tb, UNIX_DIAG_MAX, (struct rtattr *)(m + 1),
		     h->nlmsg_len - NLMSG_LENGTH(sizeof(*m)));

	return unix_collect_one(m, tb);
}

int fix_external_unix_sockets(void)
{
	struct unix_sk_desc *sk;

	pr_debug("Dumping external sockets\n");

	list_for_each_entry(sk, &unix_sockets, list) {
		struct unix_sk_entry e = { };

		BUG_ON(sk->sd.already_dumped);

		if (!opts.ext_unix_sk) {
			show_one_unix("Runaway socket", sk);
			goto err;
		}

		if (sk->type != SOCK_DGRAM) {
			show_one_unix("Ext stream not supported", sk);
			goto err;
		}

		e.id		= fd_id_generate_special();
		e.ino		= sk->sd.ino;
		e.type		= SOCK_DGRAM;
		e.state		= TCP_LISTEN;
		e.namelen	= sk->namelen;
		e.uflags	= USK_EXTERN;
		e.peer		= 0;

		show_one_unix("Dumping extern", sk);

		if (write_img(fdset_fd(glob_fdset, CR_FD_UNIXSK), &e))
			goto err;
		if (write_img_buf(fdset_fd(glob_fdset, CR_FD_UNIXSK),
					sk->name, e.namelen))
			goto err;

		show_one_unix_img("Dumped extern", &e);
	}

	return 0;
err:
	return -1;
}

struct unix_sk_info {
	struct unix_sk_entry *ue;
	struct list_head list;
	char *name;
	unsigned flags;
	struct unix_sk_info *peer;
	struct file_desc d;
};

#define USK_PAIR_MASTER		0x1
#define USK_PAIR_SLAVE		0x2

static struct unix_sk_info *find_unix_sk_by_ino(int ino)
{
	struct unix_sk_info *ui;

	list_for_each_entry(ui, &unix_sockets, list) {
		if (ui->ue->ino == ino)
			return ui;
	}

	return NULL;
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

		pr_msg("id %#x ino %#x type %s state %s namelen %4d backlog %4d peer %#x flags %#x uflags %#x",
			ue.id, ue.ino, sktype2s(ue.type), skstate2s(ue.state),
			ue.namelen, ue.backlog, ue.peer, ue.flags, ue.uflags);

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

		show_socket_opts(&ue.opts);
	}
out:
	pr_img_tail(CR_FD_UNIXSK);
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

		pr_info("\tConnect %#x to %#x\n", ui->ue->ino, peer->ue->ino);

		fle = file_master(&ui->d);

		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		memcpy(&addr.sun_path, peer->name, peer->ue->namelen);
try_again:
		if (connect(fle->fe->fd, (struct sockaddr *)&addr,
					sizeof(addr.sun_family) +
					peer->ue->namelen) < 0) {
			if (attempts) {
				usleep(1000);
				attempts--;
				goto try_again; /* FIXME use futex waiters */
			}

			pr_perror("Can't connect %#x socket", ui->ue->ino);
			return -1;
		}

		if (restore_sk_queue(fle->fe->fd, peer->ue->id))
			return -1;

		if (rst_file_params(fle->fe->fd, &ui->ue->fown, ui->ue->flags))
			return -1;

		if (restore_socket_opts(fle->fe->fd, &ui->ue->opts))
			return -1;

		cj = cj->next;
	}

	return 0;
}

static int bind_unix_sk(int sk, struct unix_sk_info *ui)
{
	struct sockaddr_un addr;

	if ((ui->ue->type == SOCK_STREAM) && (ui->ue->state != TCP_LISTEN))
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
	memcpy(&addr.sun_path, ui->name, ui->ue->namelen);

	if (bind(sk, (struct sockaddr *)&addr,
				sizeof(addr.sun_family) + ui->ue->namelen)) {
		pr_perror("Can't bind socket");
		return -1;
	}
done:
	return 0;
}

static int unixsk_should_open_transport(FdinfoEntry *fe,
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

	pr_info("Opening pair master (id %#x ino %#x peer %#x)\n",
			ui->ue->id, ui->ue->ino, ui->ue->peer);

	if (socketpair(PF_UNIX, ui->ue->type, 0, sk) < 0) {
		pr_perror("Can't make socketpair");
		return -1;
	}

	if (restore_sk_queue(sk[0], peer->ue->id))
		return -1;
	if (restore_sk_queue(sk[1], ui->ue->id))
		return -1;

	if (bind_unix_sk(sk[0], ui))
		return -1;

	if (rst_file_params(sk[0], &ui->ue->fown, ui->ue->flags))
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

	pr_info("Opening pair slave (id %#x ino %#x peer %#x) on %d\n",
			ui->ue->id, ui->ue->ino, ui->ue->peer, fle->fe->fd);

	sk = recv_fd(fle->fe->fd);
	if (sk < 0) {
		pr_err("Can't recv pair slave");
		return -1;
	}
	close(fle->fe->fd);

	if (bind_unix_sk(sk, ui))
		return -1;

	if (rst_file_params(sk, &ui->ue->fown, ui->ue->flags))
		return -1;

	if (restore_socket_opts(sk, &ui->ue->opts))
		return -1;

	return sk;
}

static int open_unixsk_standalone(struct unix_sk_info *ui)
{
	int sk;

	pr_info("Opening standalone socket (id %#x ino %#x peer %#x)\n",
			ui->ue->id, ui->ue->ino, ui->ue->peer);

	sk = socket(PF_UNIX, ui->ue->type, 0);
	if (sk < 0) {
		pr_perror("Can't make unix socket");
		return -1;
	}

	if (bind_unix_sk(sk, ui))
		return -1;

	if (ui->ue->state == TCP_LISTEN) {
		pr_info("\tPutting %#x into listen state\n", ui->ue->ino);
		if (listen(sk, ui->ue->backlog) < 0) {
			pr_perror("Can't make usk listen");
			return -1;
		}

		if (rst_file_params(sk, &ui->ue->fown, ui->ue->flags))
			return -1;

		if (restore_socket_opts(sk, &ui->ue->opts))
			return -1;

	} else if (ui->peer) {
		pr_info("\tWill connect %#x to %#x later\n", ui->ue->ino, ui->ue->peer);
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
	.type = FDINFO_UNIXSK,
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

		ui->ue = xmalloc(sizeof(*ui->ue));
		if (ui->ue == NULL)
			break;

		ret = read_img_eof(fd, ui->ue);
		if (ret <= 0) {
			xfree(ui);
			break;
		}

		if (ui->ue->namelen) {
			ret = -1;

			if (!ui->ue->namelen || ui->ue->namelen >= UNIX_PATH_MAX) {
				pr_err("Bad unix name len %d\n", ui->ue->namelen);
				break;
			}

			ui->name = xmalloc(ui->ue->namelen);
			if (ui->name == NULL)
				break;

			ret = read_img_buf(fd, ui->name, ui->ue->namelen);
			if (ret < 0)
				break;

			/*
			 * Make FS clean from sockets we're about to
			 * restore. See for how we bind them for details
			 */
			if (ui->name[0] != '\0' &&
			    !(ui->ue->uflags & USK_EXTERN))
				unlink(ui->name);
		} else
			ui->name = NULL;

		ui->peer = NULL;
		ui->flags = 0;
		pr_info(" `- Got 0x%x peer 0x%x\n", ui->ue->ino, ui->ue->peer);
		file_desc_add(&ui->d, ui->ue->id, &unix_desc_ops);
		list_add_tail(&ui->list, &unix_sockets);
	}

	close(fd);

	return read_sk_queues();
}

int resolve_unix_peers(void)
{
	struct unix_sk_info *ui, *peer;
	struct fdinfo_list_entry *fle, *fle_peer;

	list_for_each_entry(ui, &unix_sockets, list) {
		if (ui->peer)
			continue;
		if (!ui->ue->peer)
			continue;

		peer = find_unix_sk_by_ino(ui->ue->peer);

		/*
		 * Connect to external sockets requires
		 * special option to be passed.
		 */
		if (peer &&
		    (peer->ue->uflags & USK_EXTERN) &&
		    !(opts.ext_unix_sk))
			peer = NULL;

		if (!peer) {
			pr_err("FATAL: Peer %#x unresolved for %#x\n",
					ui->ue->peer, ui->ue->ino);
			return -1;
		}

		ui->peer = peer;
		if (ui == peer)
			/* socket connected to self %) */
			continue;
		if (peer->ue->peer != ui->ue->ino)
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
				 fle->fe->fd < fle_peer->fe->fd)) {
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

		pr_info("\t%#x -> %#x (%#x) flags %#x\n", ui->ue->ino, ui->ue->peer,
				ui->peer ? ui->peer->ue->ino : 0, ui->flags);
		list_for_each_entry(fle, &ui->d.fd_info_head, desc_list)
			pr_info("\t\tfd %d in pid %d\n",
					fle->fe->fd, fle->pid);

	}

	return 0;
}

