#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <libnl3/netlink/msg.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/un.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "libnetlink.h"
#include "cr_options.h"
#include "imgset.h"
#include "unix_diag.h"
#include "files.h"
#include "file-ids.h"
#include "log.h"
#include "util.h"
#include "util-pie.h"
#include "sockets.h"
#include "sk-queue.h"
#include "mount.h"
#include "cr-service.h"
#include "plugin.h"
#include "namespaces.h"
#include "pstree.h"
#include "external.h"
#include "crtools.h"

#include "protobuf.h"
#include "images/sk-unix.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "sk unix: "

/*
 * By-default, when dumping a unix socket, we should dump its peer
 * as well. Which in turn means, we should dump the task(s) that have
 * this peer opened.
 *
 * Sometimes, we can break this rule and dump only one end of the
 * unix sockets pair, and on restore time connect() this end back to
 * its peer.
 *
 * So, to resolve this situation we mark the peers we don't dump
 * as "external" and require the --ext-unix-sk option.
 */

#define USK_EXTERN	(1 << 0)
#define USK_SERVICE	(1 << 1)
#define USK_CALLBACK	(1 << 2)
#define USK_INHERIT	(1 << 3)

typedef struct {
	char			*dir;
	unsigned int		udiag_vfs_dev;
	unsigned int		udiag_vfs_ino;
} rel_name_desc_t;

struct unix_sk_desc {
	struct socket_desc	sd;
	unsigned int		type;
	unsigned int		state;
	unsigned int		peer_ino;
	unsigned int		rqlen;
	unsigned int		wqlen;
	unsigned int		namelen;
	char			*name;
	rel_name_desc_t		*rel_name;
	unsigned int		nr_icons;
	unsigned int		*icons;
	unsigned char		shutdown;
	bool			deleted;

	mode_t			mode;
	uid_t			uid;
	gid_t			gid;

	struct list_head	list;

	int			fd;
	struct list_head	peer_list;
	struct list_head	peer_node;

	UnixSkEntry		*ue;
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
	pr_debug("\t%s: ino %#x peer_ino %#x family %4d type %4d state %2d name %s\n",
		act, sk->sd.ino, sk->peer_ino, sk->sd.family, sk->type, sk->state, sk->name);

	if (sk->nr_icons) {
		int i;

		for (i = 0; i < sk->nr_icons; i++)
			pr_debug("\t\ticon: %4d\n", sk->icons[i]);
	}
}

static void show_one_unix_img(const char *act, const UnixSkEntry *e)
{
	pr_info("\t%s: id %#x ino %#x peer %#x type %d state %d name %d bytes\n",
		act, e->id, e->ino, e->peer, e->type, e->state, (int)e->name.len);
}

static int can_dump_unix_sk(const struct unix_sk_desc *sk)
{
	/*
	 * The last case in this "if" is seqpacket socket,
	 * that is connected to cr_service. We will dump
	 * it properly below.
	 */
	if (sk->type != SOCK_STREAM &&
	    sk->type != SOCK_DGRAM &&
	    sk->type != SOCK_SEQPACKET) {
		pr_err("Unsupported type (%d) on socket %x.\n"
				"Only stream/dgram/seqpacket are supported.\n",
				sk->type, sk->sd.ino);
		return 0;
	}

	switch (sk->state) {
	case TCP_LISTEN:
	case TCP_ESTABLISHED:
	case TCP_CLOSE:
		break;
	default:
		pr_err("Unknown state %d for unix socket %x\n",
				sk->state, sk->sd.ino);
		return 0;
	}

	return 1;
}

static bool unix_sk_exception_lookup_id(unsigned int ino)
{
	char id[20];

	snprintf(id, sizeof(id), "unix[%u]", ino);
	if (external_lookup_id(id)) {
		pr_debug("Found ino %u in exception unix sk list\n", (unsigned int)ino);
		return true;
	}

	return false;
}

static int write_unix_entry(struct unix_sk_desc *sk)
{
	int ret;

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_UNIXSK), sk->ue, PB_UNIX_SK);

	show_one_unix_img("Dumped", sk->ue);

	release_skopts(sk->ue->opts);
	xfree(sk->ue);

	sk->ue = NULL;

	return ret;
}

static int resolve_rel_name(struct unix_sk_desc *sk, const struct fd_parms *p)
{
	rel_name_desc_t *rel_name = sk->rel_name;
	const char *dirs[] = { "cwd", "root" };
	struct pstree_item *task;
	int mntns_root, i;
	struct ns_id *ns;

	task = pstree_item_by_real(p->pid);
	if (!task) {
		pr_err("Can't find task with pid %d\n", p->pid);
		return -ENOENT;
	}

	ns = lookup_ns_by_id(task->ids->mnt_ns_id, &mnt_ns_desc);
	if (!ns) {
		pr_err("Can't resolve mount namespace for pid %d\n", p->pid);
		return -ENOENT;
	}

	mntns_root = mntns_get_root_fd(ns);
	if (mntns_root < 0) {
		pr_err("Can't resolve fs root for pid %d\n", p->pid);
		return -ENOENT;
	}

	pr_debug("Resolving relative name %s for socket %x\n",
		 sk->name, sk->sd.ino);

	for (i = 0; i < ARRAY_SIZE(dirs); i++) {
		char dir[PATH_MAX], path[PATH_MAX];
		struct stat st;
		int ret;

		snprintf(path, sizeof(path), "/proc/%d/%s", p->pid, dirs[i]);
		ret = readlink(path, dir, sizeof(dir));
		if (ret < 0 || (size_t)ret == sizeof(dir)) {
			pr_err("Can't readlink for %s\n", dirs[i]);
			return -1;
		}
		dir[ret] = 0;

		snprintf(path, sizeof(path), ".%s/%s", dir, sk->name);
		if (fstatat(mntns_root, path, &st, 0)) {
			if (errno == ENOENT)
				continue;
			goto err;
		}

		if ((st.st_ino == rel_name->udiag_vfs_ino) &&
		    phys_stat_dev_match(st.st_dev, rel_name->udiag_vfs_dev, ns, &path[1])) {
			rel_name->dir = xstrdup(dir);
			if (!rel_name->dir)
				return -ENOMEM;

			pr_debug("Resolved relative socket name to dir %s\n", rel_name->dir);
			sk->mode = st.st_mode;
			sk->uid	= st.st_uid;
			sk->gid	= st.st_gid;
			return 0;
		}
	}

err:
	pr_err("Can't resolve name for socket %#x\n", rel_name->udiag_vfs_ino);
	return -ENOENT;
}

static int dump_one_unix_fd(int lfd, u32 id, const struct fd_parms *p)
{
	struct unix_sk_desc *sk, *peer;
	UnixSkEntry *ue;
	SkOptsEntry *skopts;
	FilePermsEntry *perms;
	FownEntry *fown;

	ue = xmalloc(sizeof(UnixSkEntry) +
			sizeof(SkOptsEntry) +
			sizeof(FilePermsEntry) +
			sizeof(FownEntry));
	if (ue == NULL)
		return -1;

	skopts = (void *) ue + sizeof(UnixSkEntry);
	perms = (void *) skopts + sizeof(SkOptsEntry);
	fown = (void *) perms + sizeof(FilePermsEntry);

	unix_sk_entry__init(ue);
	sk_opts_entry__init(skopts);
	file_perms_entry__init(perms);

	*fown = p->fown;

	sk = (struct unix_sk_desc *)lookup_socket(p->stat.st_ino, PF_UNIX, 0);
	if (IS_ERR_OR_NULL(sk)) {
		pr_err("Unix socket %#x not found\n", (int)p->stat.st_ino);
		goto err;
	}

	if (!can_dump_unix_sk(sk))
		goto err;

	BUG_ON(sk->sd.already_dumped);

	ue->name.len	= (size_t)sk->namelen;
	ue->name.data	= (void *)sk->name;

	ue->id		= id;
	ue->ino		= sk->sd.ino;
	ue->type	= sk->type;
	ue->state	= sk->state;
	ue->flags	= p->flags;
	ue->backlog	= sk->wqlen;
	ue->peer	= sk->peer_ino;
	ue->fown	= fown;
	ue->opts	= skopts;
	ue->uflags	= 0;

	if (sk->rel_name) {
		if (resolve_rel_name(sk, p))
			goto err;
		ue->name_dir = sk->rel_name->dir;
	}

	/*
	 * Check if this socket is connected to criu service.
	 * Dump it like closed one and mark it for restore.
	 */
	if (unlikely(ue->peer == service_sk_ino)) {
		ue->state = TCP_CLOSE;
		ue->peer = 0;
		ue->uflags |= USK_SERVICE;
	}

	if (sk->namelen && *sk->name) {
		ue->file_perms = perms;

		perms->mode	= sk->mode;
		perms->uid	= userns_uid(sk->uid);
		perms->gid	= userns_gid(sk->gid);
	}

	if (sk->deleted) {
		ue->has_deleted = true;
		ue->deleted	= sk->deleted;
	}

	sk_encode_shutdown(ue, sk->shutdown);

	if (ue->peer) {
		peer = (struct unix_sk_desc *)lookup_socket(ue->peer, PF_UNIX, 0);
		if (IS_ERR_OR_NULL(peer)) {
			pr_err("Unix socket %#x without peer %#x\n",
					ue->ino, ue->peer);
			goto err;
		}

		/*
		 * Peer should have us as peer or have a name by which
		 * we can access one.
		 */
		if (peer->peer_ino != ue->ino) {
			if (!peer->name) {
				pr_err("Unix socket %#x with unreachable peer %#x (%#x/%s)\n",
				       ue->ino, ue->peer, peer->peer_ino, peer->name);
				goto err;
			}
		}

		/*
		 * It can be external socket, so we defer dumping
		 * until all sockets the program owns are processed.
		 */
		if (!peer->sd.already_dumped) {
			show_one_unix("Add a peer", peer);
			list_add(&sk->peer_node, &peer->peer_list);
			sk->fd = dup(lfd);
			if (sk->fd < 0) {
				pr_perror("Unable to dup(%d)", lfd);
				goto err;
			}
		}

		if ((ue->type != SOCK_DGRAM) && (
				((ue->shutdown == SK_SHUTDOWN__READ)  &&
				 (peer->shutdown != SK_SHUTDOWN__WRITE)) ||
				((ue->shutdown == SK_SHUTDOWN__WRITE) &&
				 (peer->shutdown != SK_SHUTDOWN__READ))  ||
				((ue->shutdown == SK_SHUTDOWN__BOTH)  &&
				 (peer->shutdown != SK_SHUTDOWN__BOTH)) )) {
			/*
			 * Usually this doesn't happen, however it's possible if
			 * socket was shut down before connect() (see sockets03.c test).
			 * On restore we will shutdown both end (iow socktes will be in
			 * matched state). This shoudn't be a problem, since kernel seems
			 * to check both ends on read()/write(). Thus mismatched sockets behave
			 * the same way as matched.
			 */
			pr_warn("Shutdown mismatch %u:%d -> %u:%d\n",
					ue->ino, ue->shutdown, peer->sd.ino, peer->shutdown);
		}
	} else if (ue->state == TCP_ESTABLISHED) {
		const struct unix_sk_listen_icon *e;

		e = lookup_unix_listen_icons(ue->ino);
		if (!e) {
			/*
			 * ESTABLISHED socket without peer and without
			 * anyone waiting for it should be semi-closed
			 * connection.
			 */

			if (ue->shutdown == SK_SHUTDOWN__BOTH) {
				pr_info("Dumping semi-closed connection\n");
				goto dump;
			}

			pr_err("Dangling connection %#x\n", ue->ino);
			goto err;
		}

		/*
		 * If this is in-flight connection we need to figure
		 * out where to connect it on restore. Thus, tune up peer
		 * id by searching an existing listening socket.
		 *
		 * Note the socket name will be found at restore stage,
		 * not now, just to reduce size of dump files.
		 */

		/* e->sk_desc is _never_ NULL */
		if (e->sk_desc->state != TCP_LISTEN) {
			pr_err("In-flight connection on "
				"non-listening socket %d\n", ue->ino);
			goto err;
		}

		ue->peer = e->sk_desc->sd.ino;

		pr_debug("\t\tFixed inflight socket %#x peer %#x)\n",
				ue->ino, ue->peer);
	}
dump:
	if (dump_socket_opts(lfd, skopts))
		goto err;

	/*
	 * If a stream listening socket has non-zero rqueue, this
	 * means there are in-flight connections waiting to get
	 * accept()-ed. We handle them separately with the "icons"
	 * (i stands for in-flight, cons -- for connections) things.
	 */
	if (sk->rqlen != 0 && !(sk->type == SOCK_STREAM &&
				sk->state == TCP_LISTEN))
		if (dump_sk_queue(lfd, id))
			goto err;

	pr_info("Dumping unix socket at %d\n", p->fd);
	show_one_unix("Dumping", sk);

	sk->ue = ue;
	/*
	 *  Postpone writing the entry if a peer isn't found yet.
	 *  It's required, because we may need to modify the entry.
	 *  For example, if a socket is external and is dumped by
	 *  a callback, the USK_CALLBACK flag must be set.
	 */
	if (list_empty(&sk->peer_node) && write_unix_entry(sk))
		return -1;

	sk->sd.already_dumped = 1;

	while (!list_empty(&sk->peer_list)) {
		struct unix_sk_desc *psk;
		psk = list_first_entry(&sk->peer_list, struct unix_sk_desc, peer_node);
		close_safe(&psk->fd);
		list_del_init(&psk->peer_node);

		if (write_unix_entry(psk))
			return -1;
	}

	return 0;

err:
	release_skopts(skopts);
	xfree(ue);
	return -1;
}

const struct fdtype_ops unix_dump_ops = {
	.type		= FD_TYPES__UNIXSK,
	.dump		= dump_one_unix_fd,
};

/*
 * Returns: < 0 on error, 0 if OK, 1 to skip the socket
 */
static int unix_process_name(struct unix_sk_desc *d, const struct unix_diag_msg *m, struct nlattr **tb)
{
	int len, ret;
	char *name;

	len = nla_len(tb[UNIX_DIAG_NAME]);
	name = xmalloc(len + 1);
	if (!name)
		return -ENOMEM;

	memcpy(name, nla_data(tb[UNIX_DIAG_NAME]), len);
	name[len] = '\0';

	if (name[0] != '\0') {
		struct unix_diag_vfs *uv;
		bool deleted = false;
		char rpath[PATH_MAX];
		struct ns_id *ns;
		struct stat st;
		int mntns_root;

		if (!tb[UNIX_DIAG_VFS]) {
			pr_err("Bound socket w/o inode %#x\n", m->udiag_ino);
			goto skip;
		}

		ns = lookup_ns_by_id(root_item->ids->mnt_ns_id, &mnt_ns_desc);
		if (!ns) {
			ret = -ENOENT;
			goto out;
		}

		mntns_root = mntns_get_root_fd(ns);
		if (mntns_root < 0) {
			ret = -ENOENT;
			goto out;
		}

		uv = RTA_DATA(tb[UNIX_DIAG_VFS]);
		if (name[0] != '/') {
			/*
			 * Relative names are be resolved later at first
			 * dump attempt.
			 */
			rel_name_desc_t *rel_name = xzalloc(sizeof(*rel_name));
			if (!rel_name) {
				ret = -ENOMEM;
				goto out;
			}
			rel_name->udiag_vfs_dev = uv->udiag_vfs_dev;
			rel_name->udiag_vfs_ino = uv->udiag_vfs_ino;

			d->rel_name = rel_name;
			goto postprone;
		}

		snprintf(rpath, sizeof(rpath), ".%s", name);
		if (fstatat(mntns_root, rpath, &st, 0)) {
			if (errno != ENOENT) {
				pr_warn("Can't stat socket %#x(%s), skipping: %m (err %d)\n",
					m->udiag_ino, rpath, errno);
				goto skip;
			}

			pr_info("unix: Dropping path %s for unlinked sk %#x\n",
				name, m->udiag_ino);
			deleted = true;
		} else if ((st.st_ino != uv->udiag_vfs_ino) ||
			   !phys_stat_dev_match(st.st_dev, uv->udiag_vfs_dev, ns, name)) {
			pr_info("unix: Dropping path %s for unlinked bound "
				"sk %#x.%#x real %#x.%#x\n",
				name, (int)st.st_dev, (int)st.st_ino,
				(int)uv->udiag_vfs_dev, (int)uv->udiag_vfs_ino);
			deleted = true;
		}

		d->mode = st.st_mode;
		d->uid	= st.st_uid;
		d->gid	= st.st_gid;

		d->deleted = deleted;
	}

postprone:
	d->namelen = len;
	d->name = name;
	return 0;

out:
	xfree(name);
	return ret;
skip:
	ret = 1;
	goto out;
}

static int unix_collect_one(const struct unix_diag_msg *m,
			    struct nlattr **tb)
{
	struct unix_sk_desc *d;
	int ret = 0;

	d = xzalloc(sizeof(*d));
	if (!d)
		return -1;

	d->type	 = m->udiag_type;
	d->state = m->udiag_state;
	INIT_LIST_HEAD(&d->list);

	INIT_LIST_HEAD(&d->peer_list);
	INIT_LIST_HEAD(&d->peer_node);
	d->fd = -1;

	if (tb[UNIX_DIAG_SHUTDOWN])
		d->shutdown = nla_get_u8(tb[UNIX_DIAG_SHUTDOWN]);
	else
		pr_err_once("No socket shutdown info\n");

	if (tb[UNIX_DIAG_PEER])
		d->peer_ino = nla_get_u32(tb[UNIX_DIAG_PEER]);

	if (tb[UNIX_DIAG_NAME]) {
		ret = unix_process_name(d, m, tb);
		if (ret < 0)
			goto err;
		else if (ret == 1)
			goto skip;
		BUG_ON(ret != 0);
	}

	if (tb[UNIX_DIAG_ICONS]) {
		int len = nla_len(tb[UNIX_DIAG_ICONS]);
		int i;

		d->icons = xmalloc(len);
		if (!d->icons)
			goto err;

		memcpy(d->icons, nla_data(tb[UNIX_DIAG_ICONS]), len);
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
	list_add_tail(&d->list, &unix_sockets);
	show_one_unix("Collected", d);

	return 0;
err:
	ret = -1;
skip:
	xfree(d->icons);
	xfree(d->name);
	xfree(d);
	return ret;
}

int unix_receive_one(struct nlmsghdr *h, void *arg)
{
	struct unix_diag_msg *m = NLMSG_DATA(h);
	struct nlattr *tb[UNIX_DIAG_MAX+1];

	nlmsg_parse(h, sizeof(struct unix_diag_msg), tb, UNIX_DIAG_MAX, NULL);

	return unix_collect_one(m, tb);
}

static int dump_external_sockets(struct unix_sk_desc *peer)
{
	struct unix_sk_desc *sk;
	int ret;

	while (!list_empty(&peer->peer_list)) {
		sk = list_first_entry(&peer->peer_list, struct unix_sk_desc, peer_node);

		ret = run_plugins(DUMP_UNIX_SK, sk->fd, sk->sd.ino);
		if (ret == -ENOTSUP) {
			if (unix_sk_exception_lookup_id(sk->sd.ino)) {
				pr_debug("found exception for unix name-less external socket.\n");
			} else {
				/* Legacy -x|--ext-unix-sk option handling */
				if (!opts.ext_unix_sk) {
					show_one_unix("Runaway socket", peer);
					pr_err("External socket is used. "
							"Consider using --" USK_EXT_PARAM " option.\n");
					return -1;
				}

				if (peer->type != SOCK_DGRAM) {
					show_one_unix("Ext stream not supported", peer);
					pr_err("Can't dump half of stream unix connection.\n");
					return -1;
				}

				if (!peer->name) {
					show_one_unix("Ext dgram w/o name", peer);
					pr_err("Can't dump name-less external socket.\n");
					pr_err("%d\n", sk->fd);
					return -1;
				}
			}
		} else if (ret < 0)
			return -1;
		else
			sk->ue->uflags |= USK_CALLBACK;

		if (write_unix_entry(sk))
			return -1;
		close_safe(&sk->fd);
		list_del_init(&sk->peer_node);
	}

	return 0;
}

int fix_external_unix_sockets(void)
{
	struct unix_sk_desc *sk;

	pr_debug("Dumping external sockets\n");

	list_for_each_entry(sk, &unix_sockets, list) {
		UnixSkEntry e = UNIX_SK_ENTRY__INIT;
		FownEntry fown = FOWN_ENTRY__INIT;
		SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;

		if (sk->sd.already_dumped ||
		    list_empty(&sk->peer_list))
			continue;

		show_one_unix("Dumping extern", sk);

		fd_id_generate_special(NULL, &e.id);
		e.ino		= sk->sd.ino;
		e.type		= SOCK_DGRAM;
		e.state		= TCP_LISTEN;
		e.name.data	= (void *)sk->name;
		e.name.len	= (size_t)sk->namelen;
		e.uflags	= USK_EXTERN;
		e.peer		= 0;
		e.fown		= &fown;
		e.opts		= &skopts;

		if (pb_write_one(img_from_set(glob_imgset, CR_FD_UNIXSK), &e, PB_UNIX_SK))
			goto err;

		show_one_unix_img("Dumped extern", &e);

		if (dump_external_sockets(sk))
			goto err;
	}

	return 0;
err:
	return -1;
}

struct unix_sk_info {
	UnixSkEntry *ue;
	struct list_head list;
	char *name;
	char *name_dir;
	unsigned flags;
	struct unix_sk_info *peer;
	struct file_desc d;
	struct list_head connected; /* List of sockets, connected to me */
	struct list_head node; /* To link in peer's connected list  */

	/*
	 * For DGRAM sockets with queues, we should only restore the queue
	 * once although it may be open by more than one tid. This is the peer
	 * that should do the queueing.
	 */
	u32 queuer;
	u8 bound:1;
	u8 listen:1;
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

static int wake_connected_sockets(struct unix_sk_info *ui)
{
	struct fdinfo_list_entry *fle;
	struct unix_sk_info *tmp;

	list_for_each_entry(tmp, &ui->connected, node) {
		fle = file_master(&tmp->d);
		set_fds_event(fle->pid);
	}
	return 0;
}

static bool peer_is_not_prepared(struct unix_sk_info *peer)
{
	if (peer->ue->state != TCP_LISTEN)
		return (!peer->bound);
	else
		return (!peer->listen);
}

static int shutdown_unix_sk(int sk, struct unix_sk_info *ui)
{
	int how;
	UnixSkEntry *ue = ui->ue;

	if (!ue->has_shutdown || ue->shutdown == SK_SHUTDOWN__NONE)
		return 0;

	how = sk_decode_shutdown(ue->shutdown);
	if (shutdown(sk, how)) {
		pr_perror("Can't shutdown unix socket");
		return -1;
	}

	pr_debug("Socket %#x is shut down %d\n", ue->ino, how);
	return 0;
}

static int restore_sk_common(int fd, struct unix_sk_info *ui)
{
	if (rst_file_params(fd, ui->ue->fown, ui->ue->flags))
		return -1;

	if (restore_socket_opts(fd, ui->ue->opts))
		return -1;

	if (shutdown_unix_sk(fd, ui))
		return -1;

	return 0;
}

static void revert_unix_sk_cwd(int *prev_cwd_fd, int *root_fd)
{
	if (*root_fd >= 0) {
		if (fchdir(*root_fd) || chroot("."))
			pr_perror("Can't revert root directory");
		close_safe(root_fd);
	}
	if (prev_cwd_fd && *prev_cwd_fd >= 0) {
		if (fchdir(*prev_cwd_fd))
			pr_perror("Can't revert working dir");
		else
			pr_debug("Reverted working dir\n");
		close(*prev_cwd_fd);
		*prev_cwd_fd = -1;
	}
}

static int prep_unix_sk_cwd(struct unix_sk_info *ui, int *prev_cwd_fd, int *prev_root_fd)
{
	static struct ns_id *root = NULL;

	*prev_cwd_fd = open(".", O_RDONLY);
	if (*prev_cwd_fd < 0) {
		pr_err("Can't open current dir\n");
		return -1;
	}

	if (prev_root_fd && (root_ns_mask & CLONE_NEWNS)) {
		if (root == NULL)
			root = lookup_ns_by_id(root_item->ids->mnt_ns_id, &mnt_ns_desc);
		*prev_root_fd = open("/", O_RDONLY);
		if (*prev_root_fd < 0) {
			pr_err("Can't open current root\n");
			goto err;
		}

		if (fchdir(root->mnt.root_fd)) {
			pr_perror("Unable to change current working dir");
			goto err;
		}
		if (chroot(".")) {
			pr_perror("Unable to change root directory");
			goto err;
		}
	}

	if (ui->name_dir) {
		if (chdir(ui->name_dir)) {
			pr_perror("Can't change working dir %s",
				  ui->name_dir);
			goto err;
		}
		pr_debug("Change working dir to %s\n", ui->name_dir);
	}

	return 0;
err:
	close_safe(prev_cwd_fd);
	if (prev_root_fd)
		close_safe(prev_root_fd);
	return -1;
}

static int post_open_unix_sk(struct file_desc *d, int fd)
{
	struct unix_sk_info *ui;
	struct unix_sk_info *peer;
	struct sockaddr_un addr;
	int cwd_fd = -1, root_fd = -1;

	ui = container_of(d, struct unix_sk_info, d);
	BUG_ON((ui->flags & (USK_PAIR_MASTER | USK_PAIR_SLAVE)) ||
			(ui->ue->uflags & (USK_CALLBACK | USK_INHERIT)));

	peer = ui->peer;
	BUG_ON(peer == NULL);

	/* Skip external sockets */
	if (!list_empty(&peer->d.fd_info_head))
		if (peer_is_not_prepared(peer))
			return 1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(&addr.sun_path, peer->name, peer->ue->name.len);

	pr_info("\tConnect %#x to %#x\n", ui->ue->ino, peer->ue->ino);

	if (prep_unix_sk_cwd(peer, &cwd_fd, NULL))
		return -1;

	if (connect(fd, (struct sockaddr *)&addr,
				sizeof(addr.sun_family) +
				peer->ue->name.len) < 0) {
		revert_unix_sk_cwd(&cwd_fd, &root_fd);
		pr_perror("Can't connect %#x socket", ui->ue->ino);
		return -1;
	}

	revert_unix_sk_cwd(&cwd_fd, &root_fd);

	if (peer->queuer == ui->ue->ino && restore_sk_queue(fd, peer->ue->id))
		return -1;

	return restore_sk_common(fd, ui);
}

static int bind_unix_sk(int sk, struct unix_sk_info *ui)
{
	struct sockaddr_un addr;
	int cwd_fd = -1, root_fd = -1;
	int ret = -1;

	if ((ui->ue->type == SOCK_STREAM) && (ui->ue->state == TCP_ESTABLISHED)) {
		/*
		 * FIXME this can be done, but for doing this properly we
		 * need to bind socket to its name, then rename one to
		 * some temporary unique one and after all the sockets are
		 * restored we should walk those temp names and rename
		 * some of them back to real ones.
		 */
		ret = 0;
		goto done;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(&addr.sun_path, ui->name, ui->ue->name.len);

	if (prep_unix_sk_cwd(ui, &cwd_fd, NULL))
		return -1;

	if (ui->ue->name.len) {
		ret = bind(sk, (struct sockaddr *)&addr,
				sizeof(addr.sun_family) + ui->ue->name.len);
		if (ret < 0) {
			if (ui->ue->has_deleted && ui->ue->deleted && errno == EADDRINUSE) {
				char temp[PATH_MAX];

				pr_info("found duplicate unix socket bound at %s\n", addr.sun_path);

				ret = snprintf(temp, sizeof(temp), "%s-%s-%d", addr.sun_path, "criu-temp", getpid());
				/* this shouldn't happen, since sun_addr is only 108 chars long */
				if (ret < 0 || ret >= sizeof(temp)) {
					pr_err("snprintf of %s failed?\n", addr.sun_path);
					goto done;
				}

				ret = rename(addr.sun_path, temp);
				if (ret < 0) {
					pr_perror("couldn't move socket for binding");
					goto done;
				}

				ret = bind(sk, (struct sockaddr *)&addr,
						sizeof(addr.sun_family) + ui->ue->name.len);
				if (ret < 0) {
					pr_perror("Can't bind socket after move");
					goto done;
				}

				ret = rename(temp, addr.sun_path);
				if (ret < 0) {
					pr_perror("couldn't move socket back");
					goto done;
				}

				/* we've handled the deleted-ness of this
				 * socket and we don't want to delete it later
				 * since it's not /this/ socket.
				 */
				ui->ue->deleted = false;

			} else {
				pr_perror("Can't bind socket");
				goto done;
			}
		}

		if (*ui->name && ui->ue->file_perms) {
			FilePermsEntry *perms = ui->ue->file_perms;
			char fname[PATH_MAX];

			if (ui->ue->name.len >= sizeof(fname)) {
				pr_err("The file name is too long\n");
				goto done;
			}

			memcpy(fname, ui->name, ui->ue->name.len);
			fname[ui->ue->name.len] = '\0';

			if (fchownat(AT_FDCWD, fname, perms->uid, perms->gid, 0) == -1) {
				pr_perror("Unable to change file owner and group");
				goto done;
			}

			if (fchmodat(AT_FDCWD, fname, perms->mode, 0) == -1) {
				pr_perror("Unable to change file mode bits");
				goto done;
			}
		}

		if (ui->ue->deleted && unlink((char *)ui->ue->name.data) < 0) {
			pr_perror("failed to unlink %s", ui->ue->name.data);
			goto done;
		}
	}

	if (ui->ue->state != TCP_LISTEN) {
		ui->bound = 1;
		wake_connected_sockets(ui);
	}

	ret = 0;
done:
	revert_unix_sk_cwd(&cwd_fd, &root_fd);
	return ret;
}

static int open_unixsk_pair_master(struct unix_sk_info *ui, int *new_fd)
{
	int sk[2];
	struct unix_sk_info *peer = ui->peer;

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

	if (restore_sk_common(sk[0], ui))
		return -1;

	if (send_desc_to_peer(sk[1], &peer->d)) {
		pr_err("Can't send pair slave\n");
		return -1;
	}

	close(sk[1]);

	*new_fd = sk[0];
	return 0;
}

static int open_unixsk_pair_slave(struct unix_sk_info *ui, int *new_fd)
{
	int sk, ret;

	ret = recv_desc_from_peer(&ui->d, &sk);
	if (ret != 0) {
		if (ret != 1)
			pr_err("Can't recv pair slave\n");
		return ret;
	}

	if (bind_unix_sk(sk, ui))
		return -1;

	if (restore_sk_common(sk, ui))
		return -1;

	*new_fd = sk;
	return 0;
}

static int open_unixsk_standalone(struct unix_sk_info *ui, int *new_fd)
{
	int sk;

	pr_info("Opening standalone socket (id %#x ino %#x peer %#x)\n",
			ui->ue->id, ui->ue->ino, ui->ue->peer);

	/*
	 * Check if this socket was connected to criu service.
	 * If so, put response, that dumping and restoring
	 * was successful.
	 */
	if (ui->ue->uflags & USK_SERVICE) {
		int sks[2];

		if (socketpair(PF_UNIX, ui->ue->type, 0, sks)) {
			pr_perror("Can't create socketpair");
			return -1;
		}

		if (send_criu_dump_resp(sks[1], true, true) == -1)
			return -1;

		close(sks[1]);
		sk = sks[0];
	} else if ((ui->ue->state == TCP_ESTABLISHED) && !ui->ue->peer) {
		int ret, sks[2];

		if (ui->ue->type != SOCK_STREAM) {
			pr_err("Non-stream socket %x in established state\n",
					ui->ue->ino);
			return -1;
		}

		if (ui->ue->shutdown != SK_SHUTDOWN__BOTH) {
			pr_err("Wrong shutdown/peer state for %x\n",
					ui->ue->ino);
			return -1;
		}

		ret = socketpair(PF_UNIX, ui->ue->type, 0, sks);
		if (ret < 0) {
			pr_perror("Can't create socketpair");
			return -1;
		}

		/*
		 * Restore queue at the one end,
		 * before closing the second one.
		 */
		if (restore_sk_queue(sks[1], ui->ue->id)) {
			pr_perror("Can't restore socket queue");
			return -1;
		}

		close(sks[1]);
		sk = sks[0];
	} else if (ui->ue->type == SOCK_DGRAM && !ui->queuer) {
		struct sockaddr_un addr;
		int sks[2];

		if (socketpair(PF_UNIX, ui->ue->type, 0, sks) < 0) {
			pr_perror("Can't create socketpair");
			return -1;
		}

		sk = sks[0];
		addr.sun_family = AF_UNSPEC;

		/*
		 * socketpair() assigns sks[1] as a peer of sks[0]
		 * (and vice versa). But in this case (not zero peer)
		 * it's impossible for other sockets to connect
		 * to sks[0] (see unix_dgram_connect()->unix_may_send()).
		 * The below is hack: we use that connect with AF_UNSPEC
		 * clears socket's peer.
		 */
		if (connect(sk, (struct sockaddr *)&addr, sizeof(addr.sun_family))) {
			pr_perror("Can't clear socket's peer");
			return -1;
		}

		/*
		 * This must be after the connect() hack, because
		 * connect() flushes receive queue.
		 */
		if (restore_sk_queue(sks[1], ui->ue->id)) {
			pr_perror("Can't restore socket queue");
			return -1;
		}
		close(sks[1]);
	} else {
		if (ui->ue->uflags & USK_CALLBACK) {
			sk = run_plugins(RESTORE_UNIX_SK, ui->ue->ino);
			if (sk >= 0)
				goto out;
		}

		/*
		 * Connect to external sockets requires
		 * special option to be passed.
		 */
		if (ui->peer && (ui->peer->ue->uflags & USK_EXTERN) &&
				!(opts.ext_unix_sk)) {
			pr_err("External socket found in image. "
					"Consider using the --" USK_EXT_PARAM
					"option to allow restoring it.\n");
			return -1;
		}


		sk = socket(PF_UNIX, ui->ue->type, 0);
		if (sk < 0) {
			pr_perror("Can't make unix socket");
			return -1;
		}
	}

	if (bind_unix_sk(sk, ui))
		return -1;

	if (ui->ue->state == TCP_LISTEN) {
		pr_info("\tPutting %#x into listen state\n", ui->ue->ino);
		if (listen(sk, ui->ue->backlog) < 0) {
			pr_perror("Can't make usk listen");
			return -1;
		}
		ui->listen = 1;
		wake_connected_sockets(ui);
	}

	if (ui->peer) {
		/*
		 * We need to connect() to the peer, but the
		 * guy might have not bind()-ed himself, so
		 * let's postpone this.
		 */
		*new_fd = sk;
		return 1;
	}

out:
	if (restore_sk_common(sk, ui))
		return -1;

	*new_fd = sk;
	return 0;
}

static int open_unix_sk(struct file_desc *d, int *new_fd)
{
	struct fdinfo_list_entry *fle;
	struct unix_sk_info *ui;
	int ret;

	fle = file_master(d);
	if (fle->stage >= FLE_OPEN)
		return post_open_unix_sk(d, fle->fe->fd);

	ui = container_of(d, struct unix_sk_info, d);

	if (inherited_fd(d, new_fd)) {
		ui->ue->uflags |= USK_INHERIT;
		ret = *new_fd >= 0 ? 0 : -1;
	} else if (ui->flags & USK_PAIR_MASTER)
		ret = open_unixsk_pair_master(ui, new_fd);
	else if (ui->flags & USK_PAIR_SLAVE)
		ret = open_unixsk_pair_slave(ui, new_fd);
	else
		ret = open_unixsk_standalone(ui, new_fd);

	return ret;
}

static char *socket_d_name(struct file_desc *d, char *buf, size_t s)
{
	struct unix_sk_info *ui;

	ui = container_of(d, struct unix_sk_info, d);

	if (snprintf(buf, s, "socket:[%d]", ui->ue->ino) >= s) {
		pr_err("Not enough room for unixsk %d identifier string\n",
				ui->ue->ino);
		return NULL;
	}

	return buf;
}

static struct file_desc_ops unix_desc_ops = {
	.type = FD_TYPES__UNIXSK,
	.open = open_unix_sk,
	.name = socket_d_name,
};

/*
 * Make FS clean from sockets we're about to
 * restore. See for how we bind them for details
 */
static void unlink_stale(struct unix_sk_info *ui)
{
	int ret, cwd_fd = -1, root_fd = -1;

	if (ui->name[0] == '\0' || (ui->ue->uflags & USK_EXTERN))
		return;

	if (prep_unix_sk_cwd(ui, &cwd_fd, &root_fd))
		return;

	ret = unlinkat(AT_FDCWD, ui->name, 0) ? -1 : 0;
	if (ret < 0) {
		pr_warn("Can't unlink stale socket %#x peer %#x (name %s dir %s)\n",
			ui->ue->ino, ui->ue->peer,
			ui->name ? (ui->name[0] ? ui->name : &ui->name[1]) : "-",
			ui->name_dir ? ui->name_dir : "-");
	}
	revert_unix_sk_cwd(&cwd_fd, &root_fd);
}

static int resolve_unix_peers(void *unused);

static int collect_one_unixsk(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct unix_sk_info *ui = o;
	static bool post_queued = false;

	ui->ue = pb_msg(base, UnixSkEntry);
	ui->name_dir = (void *)ui->ue->name_dir;

	if (ui->ue->peer && !post_queued) {
		post_queued = true;
		if (add_post_prepare_cb(resolve_unix_peers, NULL))
			return -1;
	}

	if (ui->ue->name.len) {
		if (ui->ue->name.len > UNIX_PATH_MAX) {
			pr_err("Bad unix name len %d\n", (int)ui->ue->name.len);
			return -1;
		}

		ui->name = (void *)ui->ue->name.data;

		unlink_stale(ui);
	} else
		ui->name = NULL;

	ui->queuer = 0;
	ui->peer = NULL;
	ui->bound = 0;
	ui->listen = 0;
	INIT_LIST_HEAD(&ui->connected);
	INIT_LIST_HEAD(&ui->node);
	ui->flags = 0;
	pr_info(" `- Got %#x peer %#x (name %s dir %s)\n",
		ui->ue->ino, ui->ue->peer,
		ui->name ? (ui->name[0] ? ui->name : &ui->name[1]) : "-",
		ui->name_dir ? ui->name_dir : "-");
	list_add_tail(&ui->list, &unix_sockets);
	return file_desc_add(&ui->d, ui->ue->id, &unix_desc_ops);
}

struct collect_image_info unix_sk_cinfo = {
	.fd_type = CR_FD_UNIXSK,
	.pb_type = PB_UNIX_SK,
	.priv_size = sizeof(struct unix_sk_info),
	.collect = collect_one_unixsk,
	.flags = COLLECT_SHARED,
};

static void set_peer(struct unix_sk_info *ui, struct unix_sk_info *peer)
{
	ui->peer = peer;
	list_add(&ui->node, &peer->connected);
}

static void interconnected_pair(struct unix_sk_info *ui, struct unix_sk_info *peer)
{
	struct fdinfo_list_entry *fle, *fle_peer;
	/*
	 * Select who will restore the pair. Check is identical to
	 * the one in pipes.c and makes sure tasks wait for each other
	 * in pids sorting order (ascending).
	 */
	fle = file_master(&ui->d);
	fle_peer = file_master(&peer->d);

	if (fdinfo_rst_prio(fle, fle_peer)) {
		ui->flags |= USK_PAIR_MASTER;
		peer->flags |= USK_PAIR_SLAVE;
	} else {
		peer->flags |= USK_PAIR_MASTER;
		ui->flags |= USK_PAIR_SLAVE;
	}
}

static int resolve_unix_peers(void *unused)
{
	struct unix_sk_info *ui, *peer;

	list_for_each_entry(ui, &unix_sockets, list) {
		if (ui->peer)
			continue;
		if (!ui->ue->peer)
			continue;

		peer = find_unix_sk_by_ino(ui->ue->peer);

		if (!peer) {
			pr_err("FATAL: Peer %#x unresolved for %#x\n",
					ui->ue->peer, ui->ue->ino);
			return -1;
		}

		set_peer(ui, peer);
		if (!peer->queuer)
			peer->queuer = ui->ue->ino;
		if (ui == peer)
			/* socket connected to self %) */
			continue;
		if (peer->ue->peer != ui->ue->ino)
			continue;

		set_peer(peer, ui);

		/* socketpair or interconnected sockets */
		interconnected_pair(ui, peer);
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

int unix_sk_id_add(unsigned int ino)
{
	char *e_str;

	e_str = xmalloc(20);
	if (!e_str)
		return -1;
	snprintf(e_str, 20, "unix[%u]", ino);
	return add_external(e_str);
}

int unix_sk_ids_parse(char *optarg)
{
	/*
	 * parsing option of the following form: --ext-unix-sk=<inode value>,<inode
	 * value>... or short form -x<inode>,<inode>...
	 */

	char *iter = optarg;

	while (*iter != '\0') {
		if (*iter == ',')
			iter++;
		else {
			unsigned int ino = strtoul(iter, &iter, 10);

			if (0 == ino) {
				pr_err("Can't parse unix socket inode from optarg: %s\n", optarg);
				return -1;
			}
			if (unix_sk_id_add(ino) < 0) {
				pr_err("Can't add unix socket inode in list: %s\n", optarg);
				return -1;
			}
		}
	}

	return 0;
}

