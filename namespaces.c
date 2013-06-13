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

struct ns_desc *ns_desc_array[] = {
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

	return pb_write_one(fd, &nfe, PB_NS_FILES);
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
	file_desc_add(&nfi->d, nfi->nfe->id, &ns_desc_ops);

	return 0;
}

int collect_ns_files(void)
{
	int ret;

	ret = collect_image(CR_FD_NS_FILES, PB_NS_FILES,
			sizeof(struct ns_file_info), collect_one_nsfile);
	if (ret < 0 && errno == ENOENT)
		ret = 0;
	return ret;
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

static int do_dump_namespaces(struct pid *ns_pid, unsigned int ns_flags)
{
	struct cr_fdset *fdset;
	int ret = 0;

	fdset = cr_ns_fdset_open(ns_pid->virt, O_DUMP);
	if (fdset == NULL)
		return -1;

	if (ns_flags & CLONE_NEWUTS) {
		pr_info("Dump UTS namespace\n");
		ret = dump_uts_ns(ns_pid->real, fdset);
		if (ret < 0)
			goto err;
	}
	if (ns_flags & CLONE_NEWIPC) {
		pr_info("Dump IPC namespace\n");
		ret = dump_ipc_ns(ns_pid->real, fdset);
		if (ret < 0)
			goto err;
	}
	if (ns_flags & CLONE_NEWNS) {
		pr_info("Dump MNT namespace (mountpoints)\n");
		ret = dump_mnt_ns(ns_pid->real, fdset);
		if (ret < 0)
			goto err;
	}
	if (ns_flags & CLONE_NEWNET) {
		pr_info("Dump NET namespace info\n");
		ret = dump_net_ns(ns_pid->real, fdset);
		if (ret < 0)
			goto err;
	}
err:
	close_cr_fdset(&fdset);
	return ret;

}

int dump_namespaces(struct pid *ns_pid, unsigned int ns_flags)
{
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

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork ns dumper");
		return -1;
	}

	if (pid == 0) {
		ret = do_dump_namespaces(ns_pid, ns_flags);
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

	pr_info("Namespaces dump complete\n");
	return 0;
}

int prepare_namespace(int pid, unsigned long clone_flags)
{
	pr_info("Restoring namespaces %d flags 0x%lx\n",
			pid, clone_flags);

	/*
	 * On netns restore we launch an IP tool, thus we
	 * have to restore it _before_ altering the mount
	 * tree (i.e. -- mnt_ns restoring)
	 */

	if ((clone_flags & CLONE_NEWNET) && prepare_net_ns(pid))
		return -1;
	if ((clone_flags & CLONE_NEWUTS) && prepare_utsns(pid))
		return -1;
	if ((clone_flags & CLONE_NEWIPC) && prepare_ipc_ns(pid))
		return -1;
	if ((clone_flags & CLONE_NEWNS)  && prepare_mnt_ns(pid))
		return -1;

	return 0;
}

int try_show_namespaces(int ns_pid)
{
	struct cr_fdset *fdset;
	int i;

	pr_msg("Namespaces for %d:\n", ns_pid);
	pr_msg("----------------------------------------\n");
	fdset = cr_ns_fdset_open(ns_pid, O_SHOW);
	if (!fdset)
		return -1;

	for (i = _CR_FD_NS_FROM + 1; i < _CR_FD_NS_TO; i++) {
		int fd;

		if (!fdset_template[i].show)
			continue;

		fd = fdset_fd(fdset, i);
		if (fd == -1)
			continue;

		fdset_template[i].show(fdset_fd(fdset, i));
	}
	pr_msg("---[ end of %d namespaces ]---\n", ns_pid);
	close_cr_fdset(&fdset);
	return 0;
}

struct ns_desc pid_ns_desc = NS_DESC_ENTRY(CLONE_NEWPID, "pid");
struct ns_desc user_ns_desc = NS_DESC_ENTRY(CLONE_NEWUSER, "user");
