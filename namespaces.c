#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdlib.h>
#include "util.h"
#include "syscall.h"
#include "uts_ns.h"
#include "ipc_ns.h"
#include "mount.h"
#include "namespaces.h"
#include "net.h"

#include "protobuf.h"
#include "protobuf/ns.pb-c.h"

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
	unsigned int kid = 0;
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

	return kid;
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

	snprintf(buf, sizeof(buf), "/proc/%d/ns/%s", pid, nd->str);
	nsfd = open(buf, O_RDONLY);
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

struct ns_id {
	unsigned int kid;
	unsigned int id;
	pid_t pid;
	struct ns_desc *nd;
	struct ns_id *next;
};

static struct ns_id *ns_ids;
static unsigned int ns_next_id = 1;
unsigned long current_ns_mask = 0;

static unsigned int lookup_ns_id(unsigned int kid, struct ns_desc *nd)
{
	struct ns_id *nsid;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next)
		if (nsid->kid == kid && nsid->nd == nd)
			return nsid->id;

	return 0;
}

static unsigned int generate_ns_id(int pid, unsigned int kid, struct ns_desc *nd)
{
	unsigned int id;
	struct ns_id *nsid;

	id = lookup_ns_id(kid, nd);
	if (id)
		return id;

	if (pid != getpid()) {
		if (pid == root_item->pid.real) {
			BUG_ON(current_ns_mask & nd->cflag);
			pr_info("Will take %s namespace in the image\n", nd->str);
			current_ns_mask |= nd->cflag;
		} else {
			pr_err("Can't dump nested %s namespace for %d\n",
					nd->str, pid);
			return 0;
		}
	}

	nsid = xmalloc(sizeof(*nsid));
	if (!nsid)
		return 0;

	nsid->id = ns_next_id++;
	nsid->kid = kid;
	nsid->nd = nd;
	nsid->next = ns_ids;
	nsid->pid = pid;
	ns_ids = nsid;

	pr_info("Collected %u.%s namespace\n", nsid->id, nd->str);

	return nsid->id;
}

static unsigned int get_ns_id(int pid, struct ns_desc *nd)
{
	int proc_dir, ret;
	unsigned int kid;
	char ns_path[10], ns_id[32];

	proc_dir = open_pid_proc(pid);
	if (proc_dir < 0)
		return 0;

	sprintf(ns_path, "ns/%s", nd->str);
	ret = readlinkat(proc_dir, ns_path, ns_id, sizeof(ns_id));
	if (ret < 0) {
		pr_perror("Can't readlink ns link");
		return 0;
	}

	kid = parse_ns_link(ns_id, ret, nd);
	BUG_ON(!kid);

	return generate_ns_id(pid, kid, nd);
}

int dump_one_ns_file(int lfd, u32 id, const struct fd_parms *p)
{
	int fd = fdset_fd(glob_fdset, CR_FD_NS_FILES);
	NsFileEntry nfe = NS_FILE_ENTRY__INIT;
	struct fd_link *link = p->link;
	unsigned int nsid;

	nsid = lookup_ns_id(link->ns_kid, link->ns_d);
	if (!nsid) {
		pr_err("No NS ID with kid %u\n", link->ns_kid);
		return -1;
	}

	nfe.id		= id;
	nfe.ns_id	= nsid;
	nfe.ns_cflag	= link->ns_d->cflag;
	nfe.flags	= p->flags;

	return pb_write_one(fd, &nfe, PB_NS_FILE);
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
	.flags = COLLECT_OPTIONAL,
};

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
	ids->net_ns_id = get_ns_id(pid, &net_ns_desc);
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

	return 0;
}

static int do_dump_namespaces(struct ns_id *ns)
{
	int ret = -1;

	switch (ns->nd->cflag) {
	case CLONE_NEWPID:
		ret = 0;
		break;
	case CLONE_NEWUTS:
		pr_info("Dump UTS namespace %d via %d\n",
				ns->id, ns->pid);
		ret = dump_uts_ns(ns->pid, ns->id);
		break;
	case CLONE_NEWIPC:
		pr_info("Dump IPC namespace %d via %d\n",
				ns->id, ns->pid);
		ret = dump_ipc_ns(ns->pid, ns->id);
		break;
	case CLONE_NEWNS:
		pr_info("Dump MNT namespace (mountpoints) %d via %d\n",
				ns->id, ns->pid);
		ret = dump_mnt_ns(ns->pid, ns->id);
		break;
	case CLONE_NEWNET:
		pr_info("Dump NET namespace info %d via %d\n",
				ns->id, ns->pid);
		ret = dump_net_ns(ns->pid, ns->id);
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
	int pid, status;
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

	ns = ns_ids;

	while (ns) {
		/* Skip current namespaces, which are in the list too  */
		if (ns->pid == getpid()) {
			ns = ns->next;
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

		ret = waitpid(pid, &status, 0);
		if (ret != pid) {
			pr_perror("Can't wait ns dumper");
			return -1;
		}

		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			pr_err("Namespaces dumping finished with error %d\n", status);
			return -1;
		}
		ns = ns->next;
	}

	pr_info("Namespaces dump complete\n");
	return 0;
}

int prepare_namespace(struct pstree_item *item, unsigned long clone_flags)
{
	pid_t pid = item->pid.virt;
	int id;

	pr_info("Restoring namespaces %d flags 0x%lx\n",
			item->pid.virt, clone_flags);

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
	id = ns_per_id ? item->ids->mnt_ns_id : pid;
	if ((clone_flags & CLONE_NEWNS)  && prepare_mnt_ns(id))
		return -1;

	return 0;
}

int try_show_namespaces(int ns_pid)
{
	struct cr_fdset *fdset;
	int i, fd, ret;
	TaskKobjIdsEntry *ids;

	pr_msg("Namespaces for %d:\n", ns_pid);

	fd = open_image(CR_FD_IDS, O_RSTR, ns_pid);
	if (fd < 0)
		return -1;
	ret = pb_read_one(fd, &ids, PB_IDS);
	close(fd);
	if (ret < 0)
		return -1;

	fdset = cr_fdset_open(ids->net_ns_id, NETNS, O_SHOW);
	if (fdset) {
		pr_msg("-------------------NETNS---------------------\n");
		for (i = _CR_FD_NETNS_FROM + 1; i < _CR_FD_NETNS_TO; i++) {
			int fd;

			fd = fdset_fd(fdset, i);
			if (fd == -1)
				continue;

			cr_parse_fd(fd, fdset_template[i].magic);
		}
		close_cr_fdset(&fdset);
	}

	fdset = cr_fdset_open(ids->ipc_ns_id, IPCNS, O_SHOW);
	if (fdset) {
		pr_msg("-------------------IPCNS---------------------\n");
		for (i = _CR_FD_IPCNS_FROM + 1; i < _CR_FD_IPCNS_TO; i++) {
			fd = fdset_fd(fdset, i);
			if (fd == -1)
				continue;

			cr_parse_fd(fd, fdset_template[i].magic);
		}
		close_cr_fdset(&fdset);
	}

	fd = open_image(CR_FD_UTSNS, O_SHOW, ids->uts_ns_id);
	if (fd >= 0) {
		pr_msg("-------------------UTSNS---------------------\n");
		cr_parse_fd(fd, fdset_template[CR_FD_UTSNS].magic);
		close(fd);
	}

	fd = open_image(CR_FD_MNTS, O_SHOW, ids->mnt_ns_id);
	if (fd > 0) {
		pr_msg("-------------------MNTNS---------------------\n");
		cr_parse_fd(fd, fdset_template[CR_FD_MNTS].magic);
		close(fd);
	}

	pr_msg("---[ end of %d namespaces ]---\n", ns_pid);
	return 0;
}

struct ns_desc pid_ns_desc = NS_DESC_ENTRY(CLONE_NEWPID, "pid");
struct ns_desc user_ns_desc = NS_DESC_ENTRY(CLONE_NEWUSER, "user");
