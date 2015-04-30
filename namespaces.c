#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdarg.h>
#include <signal.h>

#include "cr-show.h"
#include "util.h"
#include "imgset.h"
#include "syscall.h"
#include "uts_ns.h"
#include "ipc_ns.h"
#include "mount.h"
#include "pstree.h"
#include "namespaces.h"
#include "net.h"

#include "protobuf.h"
#include "protobuf/ns.pb-c.h"
#include "protobuf/userns.pb-c.h"

static struct ns_desc *ns_desc_array[] = {
	&net_ns_desc,
	&uts_ns_desc,
	&ipc_ns_desc,
	&pid_ns_desc,
	&user_ns_desc,
	&mnt_ns_desc,
};

static unsigned int parse_ns_link(char *link, size_t len, struct ns_desc *d)
{
	unsigned long kid = 0;
	char *end;

	if (len >= d->len + 2) {
		if (link[d->len] == ':' && !memcmp(link, d->str, d->len)) {
			kid = strtoul(&link[d->len + 2], &end, 10);
			if (end && *end == ']')
				BUG_ON(kid > UINT_MAX);
			else
				kid = 0;
		}
	}

	return (unsigned int)kid;
}

bool check_ns_proc(struct fd_link *link)
{
	unsigned int i, kid;

	for (i = 0; i < ARRAY_SIZE(ns_desc_array); i++) {
		kid = parse_ns_link(link->name + 1, link->len - 1, ns_desc_array[i]);
		if (!kid)
			continue;

		link->ns_d = ns_desc_array[i];
		link->ns_kid = kid;
		return true;
	}

	return false;
}

int switch_ns(int pid, struct ns_desc *nd, int *rst)
{
	char buf[32];
	int nsfd;
	int ret = -1;

	nsfd = open_proc(pid, "ns/%s", nd->str);
	if (nsfd < 0) {
		pr_perror("Can't open ipcns file");
		goto err_ns;
	}

	if (rst) {
		snprintf(buf, sizeof(buf), "/proc/self/ns/%s", nd->str);
		*rst = open(buf, O_RDONLY);
		if (*rst < 0) {
			pr_perror("Can't open ns file");
			goto err_rst;
		}
	}

	ret = setns(nsfd, nd->cflag);
	if (ret < 0) {
		pr_perror("Can't setns %d/%s", pid, nd->str);
		goto err_set;
	}

	close(nsfd);
	return 0;

err_set:
	if (rst)
		close(*rst);
err_rst:
	close(nsfd);
err_ns:
	return -1;
}

int restore_ns(int rst, struct ns_desc *nd)
{
	int ret;

	ret = setns(rst, nd->cflag);
	if (ret < 0)
		pr_perror("Can't restore ns back");

	close(rst);

	return ret;
}

struct ns_id *ns_ids = NULL;
static unsigned int ns_next_id = 1;
unsigned long root_ns_mask = 0;

static void nsid_add(struct ns_id *ns, struct ns_desc *nd, unsigned int id, pid_t pid)
{
	ns->nd = nd;
	ns->id = id;
	ns->pid = pid;
	ns->next = ns_ids;
	ns_ids = ns;

	pr_info("Add %s ns %d pid %d\n", nd->str, ns->id, ns->pid);
}

struct ns_id *rst_new_ns_id(unsigned int id, pid_t pid, struct ns_desc *nd)
{
	struct ns_id *nsid;

	nsid = shmalloc(sizeof(*nsid));
	if (nsid) {
		nsid_add(nsid, nd, id, pid);
		futex_set(&nsid->ns_created, 0);
	}

	return nsid;
}

int rst_add_ns_id(unsigned int id, pid_t pid, struct ns_desc *nd)
{
	struct ns_id *nsid;

	nsid = lookup_ns_by_id(id, nd);
	if (nsid) {
		if (pid_rst_prio(pid, nsid->pid))
			nsid->pid = pid;
		return 0;
	}

	nsid = rst_new_ns_id(id, pid, nd);
	if (nsid == NULL)
		return -1;

	return 0;
}

static struct ns_id *lookup_ns_by_kid(unsigned int kid, struct ns_desc *nd)
{
	struct ns_id *nsid;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next)
		if (nsid->kid == kid && nsid->nd == nd)
			return nsid;

	return NULL;
}

struct ns_id *lookup_ns_by_id(unsigned int id, struct ns_desc *nd)
{
	struct ns_id *nsid;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next)
		if (nsid->id == id && nsid->nd == nd)
			return nsid;

	return NULL;
}

/*
 * For all namespaces we support, there are two supported
 * tasks-to-namespaces layout.
 *
 * If root task lives in the same namespace as criu does
 * all other tasks should live in it too and we do NOT dump
 * this namespace. On restore tasks inherit the respective
 * namespace from criu.
 *
 * If root task lives in its own namespace, then all other
 * tasks may live in it. Sometimes (CLONE_SUBNS) there can
 * be more than one namespace of that type. For this case
 * we dump all namespace's info and recreate them on restore.
 */

int walk_namespaces(struct ns_desc *nd, int (*cb)(struct ns_id *, void *), void *oarg)
{
	int ret = 0;
	struct ns_id *ns;

	for (ns = ns_ids; ns != NULL; ns = ns->next) {
		if (ns->nd != nd)
			continue;

		if (ns->pid == getpid()) {
			if (root_ns_mask & nd->cflag)
				continue;

			ret = cb(ns, oarg);
			break;
		}

		ret = cb(ns, oarg);
		if (ret)
			break;
	}

	return ret;
}

static unsigned int generate_ns_id(int pid, unsigned int kid, struct ns_desc *nd,
		struct ns_id **ns_ret)
{
	struct ns_id *nsid;

	nsid = lookup_ns_by_kid(kid, nd);
	if (nsid)
		goto found;

	if (pid != getpid()) {
		if (pid == root_item->pid.real) {
			BUG_ON(root_ns_mask & nd->cflag);
			pr_info("Will take %s namespace in the image\n", nd->str);
			root_ns_mask |= nd->cflag;
		} else if (nd->cflag & ~CLONE_SUBNS) {
			pr_err("Can't dump nested %s namespace for %d\n",
					nd->str, pid);
			return 0;
		}
	}

	nsid = xmalloc(sizeof(*nsid));
	if (!nsid)
		return 0;

	nsid->kid = kid;
	nsid_add(nsid, nd, ns_next_id++, pid);

found:
	if (ns_ret)
		*ns_ret = nsid;
	return nsid->id;
}

static unsigned int __get_ns_id(int pid, struct ns_desc *nd, struct ns_id **ns)
{
	int proc_dir, ret;
	unsigned int kid;
	char ns_path[10], ns_id[32];

	proc_dir = open_pid_proc(pid);
	if (proc_dir < 0)
		return 0;

	sprintf(ns_path, "ns/%s", nd->str);
	ret = readlinkat(proc_dir, ns_path, ns_id, sizeof(ns_id) - 1);
	if (ret < 0) {
		if (errno == ENOENT) {
			/* The namespace is unsupported */
			kid = 0;
			goto out;
		}
		pr_perror("Can't readlink ns link");
		return 0;
	}
	ns_id[ret] = '\0';

	kid = parse_ns_link(ns_id, ret, nd);
	BUG_ON(!kid);

out:
	return generate_ns_id(pid, kid, nd, ns);
}

static unsigned int get_ns_id(int pid, struct ns_desc *nd)
{
	return __get_ns_id(pid, nd, NULL);
}

int dump_one_ns_file(int lfd, u32 id, const struct fd_parms *p)
{
	struct cr_img *img = img_from_set(glob_imgset, CR_FD_NS_FILES);
	NsFileEntry nfe = NS_FILE_ENTRY__INIT;
	struct fd_link *link = p->link;
	struct ns_id *nsid;

	nsid = lookup_ns_by_kid(link->ns_kid, link->ns_d);
	if (!nsid) {
		pr_err("No NS ID with kid %u\n", link->ns_kid);
		return -1;
	}

	nfe.id		= id;
	nfe.ns_id	= nsid->id;
	nfe.ns_cflag	= link->ns_d->cflag;
	nfe.flags	= p->flags;

	return pb_write_one(img, &nfe, PB_NS_FILE);
}

const struct fdtype_ops nsfile_dump_ops = {
	.type		= FD_TYPES__NS,
	.dump		= dump_one_ns_file,
};

struct ns_file_info {
	struct file_desc	d;
	NsFileEntry		*nfe;
};

static int open_ns_fd(struct file_desc *d)
{
	struct ns_file_info *nfi = container_of(d, struct ns_file_info, d);
	struct pstree_item *item, *t;
	struct ns_desc *nd = NULL;
	char path[64];
	int fd;

	/*
	 * Find out who can open us.
	 *
	 * FIXME I need a hash or RBtree here.
	 */
	for_each_pstree_item(t) {
		TaskKobjIdsEntry *ids = t->ids;

		if (ids->pid_ns_id == nfi->nfe->ns_id) {
			item = t;
			nd = &pid_ns_desc;
			break;
		} else if (ids->net_ns_id == nfi->nfe->ns_id) {
			item = t;
			nd = &net_ns_desc;
			break;
		} else if (ids->ipc_ns_id == nfi->nfe->ns_id) {
			item = t;
			nd = &ipc_ns_desc;
			break;
		} else if (ids->uts_ns_id == nfi->nfe->ns_id) {
			item = t;
			nd = &uts_ns_desc;
			break;
		} else if (ids->mnt_ns_id == nfi->nfe->ns_id) {
			item = t;
			nd = &mnt_ns_desc;
			break;
		}
	}

	if (!nd || !item) {
		pr_err("Can't find suitable NS ID for %#x\n", nfi->nfe->ns_id);
		return -1;
	}

	if (nd->cflag != nfi->nfe->ns_cflag) {
		pr_err("Clone flag mismatch for %#x\n", nfi->nfe->ns_id);
		return -1;
	}

	snprintf(path, sizeof(path) - 1, "/proc/%d/ns/%s", item->pid.virt, nd->str);
	path[sizeof(path) - 1] = '\0';

	fd = open(path, nfi->nfe->flags);
	if (fd < 0) {
		pr_perror("Can't open file %s on restore", path);
		return fd;
	}

	return fd;
}

static struct file_desc_ops ns_desc_ops = {
	.type = FD_TYPES__NS,
	.open = open_ns_fd,
};

static int collect_one_nsfile(void *o, ProtobufCMessage *base)
{
	struct ns_file_info *nfi = o;

	nfi->nfe = pb_msg(base, NsFileEntry);
	pr_info("Collected ns file ID %#x NS-ID %#x\n", nfi->nfe->id, nfi->nfe->ns_id);
	return file_desc_add(&nfi->d, nfi->nfe->id, &ns_desc_ops);
}

struct collect_image_info nsfile_cinfo = {
	.fd_type = CR_FD_NS_FILES,
	.pb_type = PB_NS_FILE,
	.priv_size = sizeof(struct ns_file_info),
	.collect = collect_one_nsfile,
};

/*
 * Same as dump_task_ns_ids(), but
 * a) doesn't keep IDs (don't need them)
 * b) generates them for mount and netns only
 *    mnt ones are needed for open_mount() in
 *    inotify pred-dump
 *    net ones are needed for parasite socket
 */

int predump_task_ns_ids(struct pstree_item *item)
{
	int pid = item->pid.real;

	if (!__get_ns_id(pid, &net_ns_desc, &dmpi(item)->netns))
		return -1;

	if (!get_ns_id(pid, &mnt_ns_desc))
		return -1;

	return 0;
}

int dump_task_ns_ids(struct pstree_item *item)
{
	int pid = item->pid.real;
	TaskKobjIdsEntry *ids = item->ids;

	ids->has_pid_ns_id = true;
	ids->pid_ns_id = get_ns_id(pid, &pid_ns_desc);
	if (!ids->pid_ns_id) {
		pr_err("Can't make pidns id\n");
		return -1;
	}

	ids->has_net_ns_id = true;
	ids->net_ns_id = __get_ns_id(pid, &net_ns_desc, &dmpi(item)->netns);
	if (!ids->net_ns_id) {
		pr_err("Can't make netns id\n");
		return -1;
	}

	ids->has_ipc_ns_id = true;
	ids->ipc_ns_id = get_ns_id(pid, &ipc_ns_desc);
	if (!ids->ipc_ns_id) {
		pr_err("Can't make ipcns id\n");
		return -1;
	}

	ids->has_uts_ns_id = true;
	ids->uts_ns_id = get_ns_id(pid, &uts_ns_desc);
	if (!ids->uts_ns_id) {
		pr_err("Can't make utsns id\n");
		return -1;
	}

	ids->has_mnt_ns_id = true;
	ids->mnt_ns_id = get_ns_id(pid, &mnt_ns_desc);
	if (!ids->mnt_ns_id) {
		pr_err("Can't make mntns id\n");
		return -1;
	}

	ids->has_user_ns_id = true;
	ids->user_ns_id = get_ns_id(pid, &user_ns_desc);
	if (!ids->user_ns_id) {
		pr_err("Can't make userns id\n");
		return -1;
	}

	return 0;
}

static UsernsEntry userns_entry = USERNS_ENTRY__INIT;

static int userns_id(int id, UidGidExtent **map, int n)
{
	int i;

	if (!(root_ns_mask & CLONE_NEWUSER))
		return id;

	for (i = 0; i < n; i++) {
		if (map[i]->lower_first <= id &&
		    map[i]->lower_first + map[i]->count > id)
			return map[i]->first + (id - map[i]->lower_first);
	}

	return -1;
}

int userns_uid(int uid)
{
	UsernsEntry *e = &userns_entry;
	return userns_id(uid, e->uid_map, e->n_uid_map);
}

int userns_gid(int gid)
{
	UsernsEntry *e = &userns_entry;
	return userns_id(gid, e->gid_map, e->n_gid_map);
}

static int parse_id_map(pid_t pid, char *name, UidGidExtent ***pb_exts)
{
	UidGidExtent *extents = NULL;
	int len = 0, size = 0, ret, i;
	FILE *f;

	f = fopen_proc(pid, "%s", name);
	if (f == NULL)
		return -1;

	ret = -1;
	while (1) {
		UidGidExtent *ext;

		if (len == size) {
			UidGidExtent *t;

			size = size * 2 + 1;
			t = xrealloc(extents, size * sizeof(UidGidExtent));
			if (t == NULL)
				break;
			extents = t;
		}

		ext = &extents[len];

		uid_gid_extent__init(ext);
		ret = fscanf(f, "%d %d %d", &ext->first,
				&ext->lower_first, &ext->count);
		if (ret != 3) {
			if (errno != 0) {
				pr_perror("Unable to parse extents");
				ret = -1;
			} else
				ret = 0;
			break;
		}
		pr_info("id_map: %d %d %d\n", ext->first, ext->lower_first, ext->count);
		len++;
	}

	fclose(f);

	if (ret)
		goto err;

	if (len) {
		*pb_exts = xmalloc(sizeof(UidGidExtent *) * len);
		if (*pb_exts == NULL)
			goto err;

		for (i = 0; i < len; i++)
			(*pb_exts)[i] = &extents[i];
	} else {
		xfree(extents);
		*pb_exts = NULL;
	}

	return len;
err:
	xfree(extents);
	return -1;
}

int collect_user_ns(struct ns_id *ns, void *oarg)
{
	/*
	 * User namespace is dumped before files to get uid and gid
	 * mappings, which are used for convirting local id-s to
	 * userns id-s (userns_uid(), userns_gid())
	 */
	if (dump_user_ns(root_item->pid.real, root_item->ids->user_ns_id))
		return -1;

	return 0;
}

int collect_user_namespaces(bool for_dump)
{
	if (!for_dump)
		return 0;

	if (!(root_ns_mask & CLONE_NEWUSER))
		return 0;

	return walk_namespaces(&net_ns_desc, collect_user_ns, NULL);
}

static int check_user_ns(int pid)
{
	int status;
	pid_t chld;

	chld = fork();
	if (chld == -1) {
		pr_perror("Unable to fork a process");
		return -1;
	}

	if (chld == 0) {
		/*
		 * Check that we are able to enter into other namespaces
		 * from the target userns namespace. This signs that these
		 * namespaces were created from the target userns.
		 */

		if (switch_ns(pid, &user_ns_desc, NULL))
			exit(-1);

		if ((root_ns_mask & CLONE_NEWNET) &&
		    switch_ns(pid, &net_ns_desc, NULL))
			exit(-1);
		if ((root_ns_mask & CLONE_NEWUTS) &&
		    switch_ns(pid, &uts_ns_desc, NULL))
			exit(-1);
		if ((root_ns_mask & CLONE_NEWIPC) &&
		    switch_ns(pid, &ipc_ns_desc, NULL))
			exit(-1);
		if ((root_ns_mask & CLONE_NEWNS) &&
		    switch_ns(pid, &mnt_ns_desc, NULL))
			exit(-1);
		exit(0);
	}

	if (waitpid(chld, &status, 0) != chld) {
		pr_perror("Unable to wait the %d process", pid);
		return -1;
	}

	if (status) {
		pr_err("One or more namespaces doesn't belong to the target user namespace\n");
		return -1;
	}

	return 0;
}

int dump_user_ns(pid_t pid, int ns_id)
{
	int ret, exit_code = -1;
	UsernsEntry *e = &userns_entry;
	struct cr_img *img;

	if (check_user_ns(pid))
		return -1;

	ret = parse_id_map(pid, "uid_map", &e->uid_map);
	if (ret < 0)
		goto err;
	e->n_uid_map = ret;

	ret = parse_id_map(pid, "gid_map", &e->gid_map);
	if (ret < 0)
		goto err;
	e->n_gid_map = ret;

	img = open_image(CR_FD_USERNS, O_DUMP, ns_id);
	if (!img)
		goto err;
	ret = pb_write_one(img, e, PB_USERNS);
	close_image(img);
	if (ret < 0)
		goto err;

	return 0;
err:
	if (e->uid_map) {
		xfree(e->uid_map[0]);
		xfree(e->uid_map);
	}
	if (e->gid_map) {
		xfree(e->gid_map[0]);
		xfree(e->gid_map);
	}
	return exit_code;
}

void free_userns_maps()
{
	if (userns_entry.n_uid_map > 0) {
		xfree(userns_entry.uid_map[0]);
		xfree(userns_entry.uid_map);
	}
	if (userns_entry.n_gid_map > 0) {
		xfree(userns_entry.gid_map[0]);
		xfree(userns_entry.gid_map);
	}
}

static int do_dump_namespaces(struct ns_id *ns)
{
	int ret;

	ret = switch_ns(ns->pid, ns->nd, NULL);
	if (ret)
		return ret;

	switch (ns->nd->cflag) {
	case CLONE_NEWUTS:
		pr_info("Dump UTS namespace %d via %d\n",
				ns->id, ns->pid);
		ret = dump_uts_ns(ns->id);
		break;
	case CLONE_NEWIPC:
		pr_info("Dump IPC namespace %d via %d\n",
				ns->id, ns->pid);
		ret = dump_ipc_ns(ns->id);
		break;
	case CLONE_NEWNET:
		pr_info("Dump NET namespace info %d via %d\n",
				ns->id, ns->pid);
		ret = dump_net_ns(ns->id);
		break;
	default:
		pr_err("Unknown namespace flag %x", ns->nd->cflag);
		break;
	}

	return ret;

}

int dump_namespaces(struct pstree_item *item, unsigned int ns_flags)
{
	struct pid *ns_pid = &item->pid;
	struct ns_id *ns;
	int pid, nr = 0;
	int ret = 0;

	/*
	 * The setns syscall is cool, we can switch to the other
	 * namespace and then return back to our initial one, but
	 * for me it's much easier just to fork another task and
	 * let it do the job, all the more so it can be done in
	 * parallel with task dumping routine.
	 *
	 * However, the question how to dump sockets from the target
	 * net namespace with this is still open
	 */

	pr_info("Dumping %d(%d)'s namespaces\n", ns_pid->virt, ns_pid->real);

	if ((ns_flags & CLONE_NEWPID) && ns_pid->virt != 1) {
		pr_err("Can't dump a pid namespace without the process init\n");
		return -1;
	}

	for (ns = ns_ids; ns; ns = ns->next) {
		/* Skip current namespaces, which are in the list too  */
		if (ns->pid == getpid())
			continue;

		switch (ns->nd->cflag) {
			/* No data for pid namespaces to dump */
			case CLONE_NEWPID:
			/* Dumped explicitly with dump_mnt_namespaces() */
			case CLONE_NEWNS:
			/* Userns is dumped before dumping tasks */
			case CLONE_NEWUSER:
				continue;
		}

		pid = fork();
		if (pid < 0) {
			pr_perror("Can't fork ns dumper");
			return -1;
		}

		if (pid == 0) {
			ret = do_dump_namespaces(ns);
			exit(ret);
		}

		nr++;
	}

	while (nr > 0) {
		int status;

		ret = waitpid(-1, &status, 0);
		if (ret < 0) {
			pr_perror("Can't wait ns dumper");
			return -1;
		}

		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			pr_err("Namespaces dumping finished with error %d\n", status);
			return -1;
		}

		nr--;
	}

	pr_info("Namespaces dump complete\n");
	return 0;
}

static int write_id_map(pid_t pid, UidGidExtent **extents, int n, char *id_map)
{
	char buf[PAGE_SIZE];
	int off = 0, i;
	int fd;

	/*
	 *  We can perform only a single write (that may contain multiple
	 *  newline-delimited records) to a uid_map and a gid_map files.
	 */
	for (i = 0; i < n; i++)
		off += snprintf(buf + off, sizeof(buf) - off,
				"%d %d %d\n", extents[i]->first,
					extents[i]->lower_first,
					extents[i]->count);

	fd = open_proc_rw(pid, "%s", id_map);
	if (fd < 0)
		return -1;
	if (write(fd, buf, off) != off) {
		pr_perror("Unable to write into %s", id_map);
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

struct unsc_msg {
	struct msghdr h;
	/*
	 * 0th is the call address
	 * 1st is the flags
	 * 2nd is the optional (NULL in responce) arguments
	 */
	struct iovec iov[3];
	char c[CMSG_SPACE(sizeof(int))];
};

#define MAX_MSG_SIZE	256

static int usernsd_pid;

static inline void unsc_msg_init(struct unsc_msg *m, uns_call_t *c,
		int *x, void *arg, size_t asize, int fd)
{
	m->h.msg_iov = m->iov;
	m->h.msg_iovlen = 2;

	m->iov[0].iov_base = c;
	m->iov[0].iov_len = sizeof(*c);
	m->iov[1].iov_base = x;
	m->iov[1].iov_len = sizeof(*x);

	if (arg) {
		m->iov[2].iov_base = arg;
		m->iov[2].iov_len = asize;
		m->h.msg_iovlen++;
	}

	m->h.msg_name = NULL;
	m->h.msg_namelen = 0;
	m->h.msg_flags = 0;

	if (fd < 0) {
		m->h.msg_control = NULL;
		m->h.msg_controllen = 0;
	} else {
		struct cmsghdr *ch;

		m->h.msg_control = &m->c;
		m->h.msg_controllen = sizeof(m->c);
		ch = CMSG_FIRSTHDR(&m->h);
		ch->cmsg_len = CMSG_LEN(sizeof(int));
		ch->cmsg_level = SOL_SOCKET;
		ch->cmsg_type = SCM_RIGHTS;
		*((int *)CMSG_DATA(ch)) = fd;
	}
}

static int unsc_msg_fd(struct unsc_msg *um)
{
	struct cmsghdr *ch;

	ch = CMSG_FIRSTHDR(&um->h);
	if (ch && ch->cmsg_len == CMSG_LEN(sizeof(int))) {
		BUG_ON(ch->cmsg_level != SOL_SOCKET);
		BUG_ON(ch->cmsg_type != SCM_RIGHTS);
		return *((int *)CMSG_DATA(ch));
	}

	return -1;
}

static int usernsd(int sk)
{
	pr_info("UNS: Daemon started\n");

	while (1) {
		struct unsc_msg um;
		static char msg[MAX_MSG_SIZE];
		uns_call_t call;
		int flags, fd, ret;

		unsc_msg_init(&um, &call, &flags, msg, sizeof(msg), 0);
		if (recvmsg(sk, &um.h, 0) <= 0) {
			pr_perror("UNS: recv req error");
			return -1;
		}

		fd = unsc_msg_fd(&um);
		pr_debug("UNS: daemon calls %p (%d, %x)\n", call, fd, flags);

		/*
		 * Caller has sent us bare address of the routine it
		 * wants to call. Since the caller is fork()-ed from the
		 * same process as the daemon is, the latter has exactly
		 * the same code at exactly the same address as the
		 * former guy has. So go ahead and just call one!
		 */

		ret = call(msg, fd);

		if (fd >= 0)
			close(fd);

		if (flags & UNS_ASYNC) {
			/*
			 * Async call failed and the called doesn't know
			 * about it. Exit now and let the stop_usernsd()
			 * check the exit code and abort the restoration.
			 *
			 * We'd get there either by the end of restore or
			 * from the next userns_call() due to failed
			 * sendmsg() in there.
			 */
			if (ret < 0) {
				pr_err("UNS: Async call failed. Exiting\n");
				return -1;
			}

			continue;
		}

		if (flags & UNS_FDOUT)
			fd = ret;
		else
			fd = -1;

		unsc_msg_init(&um, &call, &ret, NULL, 0, fd);
		if (sendmsg(sk, &um.h, 0) <= 0) {
			pr_perror("UNS: send resp error");
			return -1;
		}

		if (fd >= 0)
			close(fd);
	}
}

int userns_call(uns_call_t call, int flags,
		void *arg, size_t arg_size, int fd)
{
	int ret, res, sk;
	bool async = flags & UNS_ASYNC;
	struct unsc_msg um;

	if (unlikely(arg_size > MAX_MSG_SIZE)) {
		pr_err("UNS: message size exceeded\n");
		return -1;
	}

	if (!usernsd_pid)
		return call(arg, fd);

	sk = get_service_fd(USERNSD_SK);
	pr_debug("UNS: calling %p (%d, %x)\n", call, fd, flags);

	if (!async)
		/*
		 * Why don't we lock for async requests? Because
		 * they just put the request in the daemon's
		 * queue and do not wait for the responce. Thus
		 * when daemon responce there's only one client
		 * waiting for it in recvmsg below, so he
		 * responces to proper caller.
		 */
		mutex_lock(&task_entries->userns_sync_lock);
	else
		/*
		 * If we want the callback to give us and FD then
		 * we should NOT do the asynchronous call.
		 */
		BUG_ON(flags & UNS_FDOUT);

	/* Send the request */

	unsc_msg_init(&um, &call, &flags, arg, arg_size, fd);
	ret = sendmsg(sk, &um.h, 0);
	if (ret <= 0) {
		pr_perror("UNS: send req error");
		ret = -1;
		goto out;
	}

	if (async) {
		ret = 0;
		goto out;
	}

	/* Get the responce back */

	unsc_msg_init(&um, &call, &res, NULL, 0, 0);
	ret = recvmsg(sk, &um.h, 0);
	if (ret <= 0) {
		pr_perror("UNS: recv resp error");
		ret = -1;
		goto out;
	}

	/* Decode the result and return */

	if (flags & UNS_FDOUT)
		ret = unsc_msg_fd(&um);
	else
		ret = res;
out:
	if (!async)
		mutex_unlock(&task_entries->userns_sync_lock);

	return ret;
}

int start_usernsd(void)
{
	int sk[2];

	if (!(root_ns_mask & CLONE_NEWUSER))
		return 0;

	/*
	 * Seqpacket to
	 *
	 * a) Help daemon distinguish individual requests from
	 *    each other easily. Stream socket require manual
	 *    messages boundaries.
	 *
	 * b) Make callers note the damon death by seeing the
	 *    disconnected socket. In case of dgram socket
	 *    callers would just get stuck in receiving the
	 *    responce.
	 */

	if (socketpair(PF_UNIX, SOCK_SEQPACKET, 0, sk)) {
		pr_perror("Can't make usernsd socket");
		return -1;
	}

	usernsd_pid = fork();
	if (usernsd_pid < 0) {
		pr_perror("Can't fork usernsd");
		close(sk[0]);
		close(sk[1]);
		return -1;
	}

	if (usernsd_pid == 0) {
		int ret;

		close(sk[0]);
		ret = usernsd(sk[1]);
		exit(ret);
	}

	close(sk[1]);
	if (install_service_fd(USERNSD_SK, sk[0]) < 0) {
		kill(usernsd_pid, SIGKILL);
		waitpid(usernsd_pid, NULL, 0);
		close(sk[0]);
		return -1;
	}

	close(sk[0]);
	return 0;
}

static int exit_usernsd(void *arg, int fd)
{
	int code = *(int *)arg;
	pr_info("UNS: `- daemon exits w/ %d\n", code);
	exit(code);
}

int stop_usernsd(void)
{
	int ret = 0;

	if (usernsd_pid) {
		int status = -1;
		sigset_t blockmask, oldmask;

		/*
		 * Don't let the sigchld_handler() mess with us
		 * calling waitpid() on the exited daemon. The
		 * same is done in cr_system().
		 */

		sigemptyset(&blockmask);
		sigaddset(&blockmask, SIGCHLD);
		sigprocmask(SIG_BLOCK, &blockmask, &oldmask);

		/*
		 * Send a message to make sure the daemon _has_
		 * proceeded all its queue of asynchronous requests.
		 *
		 * All the restoring processes might have already
		 * closed their USERNSD_SK descriptors, but daemon
		 * still has its in connected state -- this is us
		 * who hold the last reference on the peer.
		 *
		 * If daemon has exited "in advance" due to async
		 * call or socket error, the userns_call() and the
		 * waitpid() below would both fail and we'll see
		 * bad exit status.
		 */

		userns_call(exit_usernsd, UNS_ASYNC, &ret, sizeof(ret), -1);
		waitpid(usernsd_pid, &status, 0);

		if (WIFEXITED(status))
			ret = WEXITSTATUS(status);
		else
			ret = -1;

		usernsd_pid = 0;
		sigprocmask(SIG_BLOCK, &oldmask, NULL);

		if (ret != 0)
			pr_err("UNS: daemon exited abnormally\n");
		else
			pr_info("UNS: daemon stopped\n");
	}

	return ret;
}

int prepare_userns(struct pstree_item *item)
{
	struct cr_img *img;
	UsernsEntry *e;
	int ret;

	img = open_image(CR_FD_USERNS, O_RSTR, item->ids->user_ns_id);
	if (!img)
		return -1;
	ret = pb_read_one(img, &e, PB_USERNS);
	close_image(img);
	if (ret < 0)
		return -1;

	if (write_id_map(item->pid.real, e->uid_map, e->n_uid_map, "uid_map"))
		return -1;

	if (write_id_map(item->pid.real, e->gid_map, e->n_gid_map, "gid_map"))
		return -1;

	return 0;
}

int collect_namespaces(bool for_dump)
{
	int ret;

	ret = collect_mnt_namespaces(for_dump);
	if (ret < 0)
		return ret;

	ret = collect_net_namespaces(for_dump);
	if (ret < 0)
		return ret;

	ret = collect_user_namespaces(for_dump);
	if (ret < 0)
		return ret;

	return 0;
}

static int prepare_userns_creds()
{
	/* UID and GID must be set after restoring /proc/PID/{uid,gid}_maps */
	if (setuid(0) || setgid(0) || setgroups(0, NULL)) {
		pr_perror("Unable to initialize id-s");
		return -1;
	}

	/*
	 * This flag is dropped after entering userns, but is
	 * required to access files in /proc, so put one here
	 * temoprarily. It will be set to proper value at the
	 * very end.
	 */
	if (prctl(PR_SET_DUMPABLE, 1, 0)) {
		pr_perror("Unable to set PR_SET_DUMPABLE");
		exit(1);
	}

	return 0;
}

int prepare_namespace(struct pstree_item *item, unsigned long clone_flags)
{
	pid_t pid = item->pid.virt;
	int id;

	pr_info("Restoring namespaces %d flags 0x%lx\n",
			item->pid.virt, clone_flags);

	if ((clone_flags & CLONE_NEWUSER) && prepare_userns_creds())
		return -1;

	/*
	 * On netns restore we launch an IP tool, thus we
	 * have to restore it _before_ altering the mount
	 * tree (i.e. -- mnt_ns restoring)
	 */

	id = ns_per_id ? item->ids->net_ns_id : pid;
	if ((clone_flags & CLONE_NEWNET) && prepare_net_ns(id))
		return -1;
	id = ns_per_id ? item->ids->uts_ns_id : pid;
	if ((clone_flags & CLONE_NEWUTS) && prepare_utsns(id))
		return -1;
	id = ns_per_id ? item->ids->ipc_ns_id : pid;
	if ((clone_flags & CLONE_NEWIPC) && prepare_ipc_ns(id))
		return -1;

	/*
	 * This one is special -- there can be several mount
	 * namespaces and prepare_mnt_ns handles them itself.
	 */
	if (prepare_mnt_ns())
		return -1;

	return 0;
}

int try_show_namespaces(int ns_pid)
{
	struct cr_imgset *imgset;
	int i, ret;
	struct cr_img *img;
	TaskKobjIdsEntry *ids;

	pr_msg("Namespaces for %d:\n", ns_pid);

	img = open_image(CR_FD_IDS, O_RSTR, ns_pid);
	if (!img)
		return -1;
	ret = pb_read_one(img, &ids, PB_IDS);
	close_image(img);
	if (ret < 0)
		return -1;

	imgset = cr_imgset_open(ids->net_ns_id, NETNS, O_SHOW);
	if (imgset) {
		pr_msg("-------------------NETNS---------------------\n");
		for (i = _CR_FD_NETNS_FROM + 1; i < _CR_FD_NETNS_TO; i++) {
			img = img_from_set(imgset, i);
			if (!img)
				continue;

			cr_parse_fd(img, imgset_template[i].magic);
		}
		close_cr_imgset(&imgset);
	}

	imgset = cr_imgset_open(ids->ipc_ns_id, IPCNS, O_SHOW);
	if (imgset) {
		pr_msg("-------------------IPCNS---------------------\n");
		for (i = _CR_FD_IPCNS_FROM + 1; i < _CR_FD_IPCNS_TO; i++) {
			img = img_from_set(imgset, i);
			if (!img)
				continue;

			cr_parse_fd(img, imgset_template[i].magic);
		}
		close_cr_imgset(&imgset);
	}

	img = open_image(CR_FD_UTSNS, O_SHOW, ids->uts_ns_id);
	if (img) {
		pr_msg("-------------------UTSNS---------------------\n");
		cr_parse_fd(img, imgset_template[CR_FD_UTSNS].magic);
		close_image(img);
	}

	img = open_image(CR_FD_MNTS, O_SHOW, ids->mnt_ns_id);
	if (img) {
		pr_msg("-------------------MNTNS---------------------\n");
		cr_parse_fd(img, imgset_template[CR_FD_MNTS].magic);
		close_image(img);
	}

	pr_msg("---[ end of %d namespaces ]---\n", ns_pid);
	return 0;
}

struct ns_desc pid_ns_desc = NS_DESC_ENTRY(CLONE_NEWPID, "pid");
struct ns_desc user_ns_desc = NS_DESC_ENTRY(CLONE_NEWUSER, "user");
