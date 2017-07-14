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
#include <sched.h>
#include <sys/capability.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/file.h>

#include "page.h"
#include "rst-malloc.h"
#include "cr_options.h"
#include "imgset.h"
#include "uts_ns.h"
#include "ipc_ns.h"
#include "mount.h"
#include "pstree.h"
#include "namespaces.h"
#include "restore.h"
#include "net.h"
#include "cgroup.h"
#include "kerndat.h"

#include "protobuf.h"
#include "util.h"
#include "util-pie.h"
#include "images/ns.pb-c.h"
#include "common/scm.h"
#include "fdstore.h"
#include "proc_parse.h"

#define __sys(foo)	foo
#define __sys_err(ret)	(-errno)

#include "ns-common.c"

static struct ns_desc *ns_desc_array[] = {
	&net_ns_desc,
	&uts_ns_desc,
	&ipc_ns_desc,
	&pid_ns_desc,
	&user_ns_desc,
	&mnt_ns_desc,
	&cgroup_ns_desc,
};

static unsigned int join_ns_flags;

int check_namespace_opts(void)
{
	errno = 22;
	if (join_ns_flags & opts.empty_ns) {
		pr_err("Conflicting flags: --join-ns and --empty-ns\n");
		return -1;
	}
	if (join_ns_flags & CLONE_NEWUSER)
		pr_warn("join-ns with user-namespace is not fully tested and dangerous");

	errno = 0;
	return 0;
}

static int check_int_str(char *str)
{
	char *endptr;
	long val;

	if (str == NULL)
		return 0;

	if (*str == '\0') {
		str = NULL;
		return 0;
	}

	errno = 22;
	val = strtol(str, &endptr, 10);
	if ((errno == ERANGE) || (endptr == str)
			|| (*endptr != '\0')
			|| (val < 0) || (val > 65535)) {
		str = NULL;
		return -1;
	}

	errno = 0;
	return 0;
}

static int check_ns_file(char *ns_file)
{
	int pid, ret, proc_dir;

	if (!check_int_str(ns_file)) {
		pid = atoi(ns_file);
		if (pid <= 0) {
			pr_err("Invalid join_ns pid %s\n", ns_file);
			return -1;
		}
		proc_dir = open_pid_proc(pid);
		if (proc_dir < 0) {
			pr_err("Invalid join_ns pid: /proc/%s not found\n",
					ns_file);
			return -1;
		}
		return 0;
	}

	ret = access(ns_file, 0);
	if (ret < 0) {
		pr_perror("Can't access join-ns file %s", ns_file);
		return -1;
	}
	return 0;
}

static int set_user_extra_opts(struct join_ns *jn, char *extra_opts)
{
	char *uid, *gid, *aux;

	if (extra_opts == NULL) {
		jn->extra_opts.user_extra.uid = NULL;
		jn->extra_opts.user_extra.gid = NULL;
		return 0;
	}

	uid = extra_opts;
	aux = strchr(extra_opts, ',');
	if (aux == NULL) {
		gid = NULL;
	} else {
		*aux = '\0';
		gid = aux + 1;
	}

	if (check_int_str(uid) || check_int_str(gid))
		return -1;

	jn->extra_opts.user_extra.uid = uid;
	jn->extra_opts.user_extra.gid = gid;

	return 0;
}

int join_ns_add(const char *type, char *ns_file, char *extra_opts)
{
	struct join_ns *jn;

	if (check_ns_file(ns_file))
		return -1;

	jn = xmalloc(sizeof(*jn));
	if (!jn)
		return -1;

	jn->ns_file = ns_file;
	if (!strncmp(type, "net", 4)) {
		jn->nd = &net_ns_desc;
		join_ns_flags |= CLONE_NEWNET;
	} else if (!strncmp(type, "uts", 4)) {
		jn->nd = &uts_ns_desc;
		join_ns_flags |= CLONE_NEWUTS;
	} else if (!strncmp(type, "ipc", 4)) {
		jn->nd = &ipc_ns_desc;
		join_ns_flags |= CLONE_NEWIPC;
	} else if (!strncmp(type, "pid", 4)) {
		pr_err("join-ns pid namespace not supported\n");
		goto err;
	} else if (!strncmp(type, "user", 5)) {
		jn->nd = &user_ns_desc;
		if (set_user_extra_opts(jn, extra_opts)) {
			pr_err("invalid user namespace extra_opts %s\n", extra_opts);
			goto err;
		}
		join_ns_flags |= CLONE_NEWUSER;
	} else if (!strncmp(type, "mnt", 4)) {
		jn->nd = &mnt_ns_desc;
		join_ns_flags |= CLONE_NEWNS;
	} else {
		pr_err("invalid namespace type %s\n", type);
		goto err;
	}

	list_add_tail(&jn->list, &opts.join_ns);
	pr_info("Added %s:%s join namespace\n", type, ns_file);
	return 0;
err:
	xfree(jn);
	return -1;
}

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
	int nsfd;
	int ret;

	nsfd = open_proc(pid, "ns/%s", nd->str);
	if (nsfd < 0)
		return -1;

	ret = switch_ns_by_fd(nsfd, nd, rst);

	close(nsfd);

	return ret;
}

int switch_ns_by_fd(int nsfd, struct ns_desc *nd, int *rst)
{
	int ret = -1;

	if (rst) {
		*rst = open_proc(PROC_SELF, "ns/%s", nd->str);
		if (*rst < 0)
			goto err_ns;
	}

	ret = setns(nsfd, nd->cflag);
	if (ret < 0) {
		pr_perror("Can't setns %d/%s", nsfd, nd->str);
		goto err_set;
	}

	return 0;

err_set:
	if (rst)
		close(*rst);
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
	ns->ns_pid = pid;
	ns->next = ns_ids;
	ns_ids = ns;

	pr_info("Add %s ns %d pid %d\n", nd->str, ns->id, ns->ns_pid);
}

struct ns_id *rst_new_ns_id(unsigned int id, pid_t pid,
		struct ns_desc *nd, enum ns_type type)
{
	struct ns_id *nsid;

	nsid = shmalloc(sizeof(*nsid));
	if (nsid) {
		nsid->type = type;
		nsid_add(nsid, nd, id, pid);
		nsid->ns_populated = false;
		INIT_LIST_HEAD(&nsid->children);
		INIT_LIST_HEAD(&nsid->siblings);

		if (nd == &net_ns_desc) {
			INIT_LIST_HEAD(&nsid->net.ids);
			INIT_LIST_HEAD(&nsid->net.links);
			nsid->net.netns = NULL;
		} else if (nd == &pid_ns_desc) {
			nsid->pid.rb_root = RB_ROOT;
			nsid->pid.nsfd_id = -1;
			futex_init(&nsid->pid.helper_created);
		}
	}

	return nsid;
}

int rst_add_ns_id(unsigned int id, pid_t pid, struct ns_desc *nd)
{
	struct ns_id *nsid;

	nsid = lookup_ns_by_id(id, nd);
	if (nsid) {
		if (nsid->ns_pid == -1 || pid_rst_prio(pid, nsid->ns_pid))
			nsid->ns_pid = pid;
		return 0;
	}

	nsid = rst_new_ns_id(id, pid, nd, NS_OTHER);
	if (nsid == NULL)
		return -1;

	return 0;
}

struct ns_id *lookup_ns_by_kid(unsigned int kid, struct ns_desc *nd)
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

		if (ns->type == NS_CRIU) {
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
		struct ns_id **ns_ret, bool alternative)
{
	struct ns_id *nsid;
	enum ns_type type;

	nsid = lookup_ns_by_kid(kid, nd);
	if (nsid)
		goto found;

	if (pid != getpid()) {
		type = NS_OTHER;
		if (pid == root_item->pid->real && !alternative) {
			BUG_ON(root_ns_mask & nd->cflag);
			pr_info("Will take %s namespace in the image\n", nd->str);
			root_ns_mask |= nd->cflag;
			type = NS_ROOT;
		} else if (nd->cflag & ~CLONE_SUBNS) {
			pr_err("Can't dump nested %s namespace for %d\n",
					nd->str, pid);
			return 0;
		}
	} else
		type = NS_CRIU;

	nsid = xzalloc(sizeof(*nsid));
	if (!nsid)
		return 0;

	nsid->type = type;
	nsid->kid = kid;
	nsid->ns_populated = true;
	INIT_LIST_HEAD(&nsid->children);
	INIT_LIST_HEAD(&nsid->siblings);
	nsid->alternative = alternative;
	nsid_add(nsid, nd, ns_next_id++, pid);
	BUG_ON(nsid->id == UINT_MAX);

	if (nd == &net_ns_desc) {
		INIT_LIST_HEAD(&nsid->net.ids);
		INIT_LIST_HEAD(&nsid->net.links);
	} else if (nd == &pid_ns_desc)
		nsid->pid.rb_root = RB_ROOT;
found:
	if (ns_ret)
		*ns_ret = nsid;
	return nsid->id;
}

static unsigned int __get_ns_id(int pid, struct ns_desc *nd, bool alternative,
				protobuf_c_boolean *supported, struct ns_id **ns)
{
	int proc_dir;
	unsigned int kid;
	char ns_path[32];
	struct stat st;

	proc_dir = open_pid_proc(pid);
	if (proc_dir < 0)
		return 0;

	snprintf(ns_path, sizeof(ns_path), "ns/%s", !alternative ? nd->str : nd->alt_str);

	if (fstatat(proc_dir, ns_path, &st, 0)) {
		if (errno == ENOENT) {
			if (alternative)
				return UINT_MAX;
			/* The namespace is unsupported */
			kid = 0;
			goto out;
		}
		pr_perror("Unable to stat %s", ns_path);
		return 0;
	}
	kid = st.st_ino;
	BUG_ON(!kid);

out:
	if (supported)
		*supported = kid != 0;
	return generate_ns_id(pid, kid, nd, ns, alternative);
}

static unsigned int get_ns_id(int pid, struct ns_desc *nd, protobuf_c_boolean *supported)
{
	return __get_ns_id(pid, nd, false, supported, NULL);
}

int dump_one_ns_file(int lfd, u32 id, const struct fd_parms *p)
{
	struct cr_img *img;
	FileEntry fe = FILE_ENTRY__INIT;
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

	fe.type = FD_TYPES__NS;
	fe.id = nfe.id;
	fe.nsf = &nfe;

	img = img_from_set(glob_imgset, CR_FD_FILES);
	return pb_write_one(img, &fe, PB_FILE);
}

static UsernsEntry *dup_userns_entry(UsernsEntry *orig)
{
	UsernsEntry *copy;
	int ret = -1;
	size_t *i;

	copy = xzalloc(sizeof(*copy));
	if (!copy)
		goto out;
#define COPY_MAP(map, n_map)								\
	do {										\
		i = &copy->n_map;							\
		copy->map = xmalloc(sizeof(UidGidExtent *) * orig->n_map);		\
		if (!copy->map)								\
			goto out;							\
		for (*i = 0; *i < orig->n_map; ++*i) {					\
			copy->map[*i] = xmalloc(sizeof(UidGidExtent));			\
			if (!copy->map)							\
				goto out;						\
			memcpy(copy->map[*i], orig->map[*i], sizeof(UidGidExtent));	\
		}									\
	} while (0)

#define FREE_MAP(map, n_map)								\
	do {										\
		if (copy->map) {							\
			i = &copy->n_map;						\
			while (--*i > 0)						\
				xfree(copy->map[*i]);					\
			xfree(copy->map);						\
		}									\
	} while (0)

	COPY_MAP(uid_map, n_uid_map);
	COPY_MAP(gid_map, n_gid_map);
	ret = 0;
out:
	if (ret) {
		pr_err("Can't dup entry\n");
		if (copy) {
			FREE_MAP(uid_map, n_uid_map);
			FREE_MAP(gid_map, n_gid_map);
			xfree(copy);
		}
		return NULL;
	}
	return copy;
}

const struct fdtype_ops nsfile_dump_ops = {
	.type		= FD_TYPES__NS,
	.dump		= dump_one_ns_file,
};

struct ns_file_info {
	struct file_desc	d;
	NsFileEntry		*nfe;
};

static int open_ns_fd(struct file_desc *d, int *new_fd)
{
	struct ns_file_info *nfi = container_of(d, struct ns_file_info, d);
	struct pstree_item *item, *t;
	struct ns_desc *nd = NULL;
	struct ns_id *ns;
	int nsfd_id, fd;
	char path[64];

	for (ns = ns_ids; ns != NULL; ns = ns->next) {
		if (ns->id != nfi->nfe->ns_id)
			continue;
		/* Check for CLONE_XXX as we use fdstore only if flag is set */
		if (ns->nd == &user_ns_desc && (root_ns_mask & CLONE_NEWUSER))
			nsfd_id = ns->user.nsfd_id;
		else if (ns->nd == &net_ns_desc && (root_ns_mask & CLONE_NEWNET))
			nsfd_id = ns->net.nsfd_id;
		else
			break;
		fd = fdstore_get(nsfd_id);
		goto check_open;
	}

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
		} else if (ids->user_ns_id == nfi->nfe->ns_id) {
			item = t;
			nd = &user_ns_desc;
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
		} else if (ids->cgroup_ns_id == nfi->nfe->ns_id) {
			item = t;
			nd = &cgroup_ns_desc;
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

	snprintf(path, sizeof(path) - 1, "/proc/%d/ns/%s", vpid(item), nd->str);
	path[sizeof(path) - 1] = '\0';

	fd = open(path, nfi->nfe->flags);
check_open:
	if (fd < 0) {
		pr_perror("Can't open file %s on restore", path);
		return fd;
	}

	*new_fd = fd;
	return 0;
}

static struct file_desc_ops ns_desc_ops = {
	.type = FD_TYPES__NS,
	.open = open_ns_fd,
};

static int collect_one_nsfile(void *o, ProtobufCMessage *base, struct cr_img *img)
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

static int get_pid_for_children_ns_id(pid_t pid, TaskKobjIdsEntry *ids)
{
	ids->has_pid_for_children_ns_id = false;

	if (kdat.has_pid_for_children_ns) {
		ids->pid_for_children_ns_id = __get_ns_id(pid, &pid_ns_desc, true,
							  &ids->has_pid_for_children_ns_id, NULL);
		if (!ids->pid_for_children_ns_id) {
			pr_err("Can't make pid_for_children id\n");
			return -1;
		}
		if (ids->pid_for_children_ns_id == UINT_MAX) {
			pr_err("Just unshared pid namespaces are not supported yet\n");
			return -1;
		}
	}
	return 0;
}

/*
 * Same as dump_task_ns_ids(), but
 * a) doesn't keep IDs (don't need them)
 * b) generates them for mount, netns and pid_ns only
 *    mnt ones are needed for open_mount() in
 *    inotify pred-dump
 *    net ones are needed for parasite socket
 *    pid is need for pid_ns_root_off()
 */

int predump_task_ns_ids(struct pstree_item *item)
{
	int pid = item->pid->real;

	if (!__get_ns_id(pid, &net_ns_desc, false,
			 NULL, &dmpi(item)->netns))
		return -1;

	if (!get_ns_id(pid, &mnt_ns_desc, NULL))
		return -1;

	if (!get_ns_id(pid, &pid_ns_desc, NULL))
		return -1;

	return 0;
}

int dump_task_ns_ids(struct pstree_item *item)
{
	int pid = item->pid->real;
	TaskKobjIdsEntry *ids = item->ids;

	ids->has_pid_ns_id = true;
	ids->pid_ns_id = get_ns_id(pid, &pid_ns_desc, NULL);
	if (!ids->pid_ns_id) {
		pr_err("Can't make pidns id\n");
		return -1;
	}

	ids->has_user_ns_id = true;
	ids->user_ns_id = get_ns_id(pid, &user_ns_desc, NULL);
	if (!ids->user_ns_id) {
		pr_err("Can't make userns id\n");
		return -1;
	}

	/* Below namespaces do not present in dead task */
	if (item->pid->state == TASK_DEAD)
		return 0;

	ids->has_net_ns_id = true;
	ids->net_ns_id = __get_ns_id(pid, &net_ns_desc, false,
				     NULL, &dmpi(item)->netns);
	if (!ids->net_ns_id) {
		pr_err("Can't make netns id\n");
		return -1;
	}

	ids->has_ipc_ns_id = true;
	ids->ipc_ns_id = get_ns_id(pid, &ipc_ns_desc, NULL);
	if (!ids->ipc_ns_id) {
		pr_err("Can't make ipcns id\n");
		return -1;
	}

	ids->has_uts_ns_id = true;
	ids->uts_ns_id = get_ns_id(pid, &uts_ns_desc, NULL);
	if (!ids->uts_ns_id) {
		pr_err("Can't make utsns id\n");
		return -1;
	}

	ids->has_mnt_ns_id = true;
	ids->mnt_ns_id = get_ns_id(pid, &mnt_ns_desc, NULL);
	if (!ids->mnt_ns_id) {
		pr_err("Can't make mntns id\n");
		return -1;
	}

	ids->cgroup_ns_id = get_ns_id(pid, &cgroup_ns_desc, &ids->has_cgroup_ns_id);
	if (!ids->cgroup_ns_id) {
		pr_err("Can't make cgroup id\n");
		return -1;
	}

	if (get_pid_for_children_ns_id(pid, ids) < 0)
		return -1;

	return 0;
}

int dump_thread_ids(pid_t pid, TaskKobjIdsEntry *ids)
{
	if (get_pid_for_children_ns_id(pid, ids) < 0)
		return -1;

	return 0;
}

static int set_ns_opt(int ns_fd, unsigned ioc, struct ns_id **ns, struct ns_desc *nd)
{
	int opt_fd, ret = -1;
	struct stat st;

	opt_fd = ioctl(ns_fd, ioc);
	if (opt_fd < 0) {
		pr_info("Can't do ns ioctl %x\n", ioc);
		return -errno;
	}
	if (fstat(opt_fd, &st) < 0) {
		pr_perror("Unable to stat on ns fd");
		ret = -errno;
		goto out;
	}
	*ns = lookup_ns_by_kid(st.st_ino, nd);
	if (!*ns) {
		pr_err("Namespaces hierarhies with holes are not supported\n");
		ret = -EINVAL;
		goto out;
	}
	ret = 0;
out:
	close(opt_fd);
	return ret;
}

static int set_ns_hookups(struct ns_id *ns)
{
	struct ns_desc *nd = ns->nd;
	struct ns_id *u_ns;
	int fd, ret = -1;

	fd = open_proc(ns->ns_pid, "ns/%s", !ns->alternative ? nd->str : nd->alt_str);
	if (fd < 0) {
		pr_perror("Can't open %s, pid %d", nd->str, ns->ns_pid);
		return -1;
	}

	if (ns->type != NS_ROOT && (nd == &pid_ns_desc || nd == &user_ns_desc)) {
		if (set_ns_opt(fd, NS_GET_PARENT, &ns->parent, nd) < 0)
			goto out;
		if (ns->parent->type == NS_CRIU) {
			pr_err("Wrong determined NS_ROOT, or root_item has NS_OTHER user_ns\n");
			goto out;
		}
		if (nd == &pid_ns_desc && !kdat.has_nspid) {
			pr_err("Can't dump nested pid ns\n");
			goto out;
		}
		list_add(&ns->siblings, &ns->parent->children);
	}

	if (nd != &user_ns_desc) {
		ret = set_ns_opt(fd, NS_GET_USERNS, &ns->user_ns, &user_ns_desc);
		if (ret == -ENOTTY) {
			u_ns = NULL;
			if (root_ns_mask & CLONE_NEWUSER) {
				/*
				 * Assume, we have the only user_ns. If it's not so,
				 * we'll later fail on NS_GET_PARENT for the second user_ns.
				 */
				pr_info("Can't get user_ns of %s %u, assuming NS_ROOT\n",
					nd->str, ns->id);
				for (u_ns = ns_ids; u_ns; u_ns = u_ns->next) {
					if (u_ns->nd == &user_ns_desc && u_ns->type == NS_ROOT)
						break;
				}
				if (!u_ns) {
					pr_err("Can't find root user_ns\n");
					goto out;
				}
			}
			ns->user_ns = u_ns;
		} else if (ret < 0) {
			goto out;
		} else if (ns->user_ns->type == NS_CRIU) {
			if (root_ns_mask & CLONE_NEWUSER) {
				pr_err("Must not be criu user_ns\n");
				ret = -1;
				goto out;
			}
			ns->user_ns = NULL;
		}
	}
	ret = 0;
out:
	close(fd);
	return ret;
}

/*
 * top_xxx_ns -- top namespaces of the dumped/restored tasks.
 * For not-hierarchical types this means namespace of root_item.
 * For hierarchical types this means the grand parent namespace,
 * which is ancestor of all others. That is, root_item may have
 * a namespace different to top_user_ns, but currently it's not
 * supported.
 * top_xxx_ns may differ to NS_ROOT(i.e., to be NS_CRIU on dump),
 * so the prefix "top" is used.
 */
struct ns_id *top_pid_ns = NULL;
struct ns_id *top_user_ns = NULL;
struct ns_id *top_net_ns = NULL;
/* Mapping NS_ROOT to NS_CRIU */
UsernsEntry *userns_entry;

bool is_subns(struct ns_id *sub_ns, struct ns_id *ns)
{
	if (!current)
		return true;

	while (sub_ns) {
		if (sub_ns == ns)
			return true;
		sub_ns = sub_ns->parent;
	}
	return false;
}

bool can_access_userns(struct ns_id *user_ns)
{
	return is_subns(user_ns, current->user_ns);
}

unsigned int child_userns_xid(unsigned int id, UidGidExtent **map, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (map[i]->lower_first <= id &&
		    map[i]->lower_first + map[i]->count > id)
			return map[i]->first + (id - map[i]->lower_first);
	}

	return NS_INVALID_XID;
}

static unsigned int parent_userns_id(unsigned int id, UidGidExtent **map, int n)
{
	int i;

	if (!(root_ns_mask & CLONE_NEWUSER))
		return id;

	for (i = 0; i < n; i++) {
		if (map[i]->first <= id &&
		    map[i]->first + map[i]->count > id)
			return map[i]->lower_first + (id - map[i]->first);
	}

	return NS_INVALID_XID;
}

static uid_t parent_userns_uid(UsernsEntry *e, uid_t uid)
{
	return parent_userns_id(uid, e->uid_map, e->n_uid_map);
}

static gid_t parent_userns_gid(UsernsEntry *e, gid_t gid)
{
	return parent_userns_id(gid, e->gid_map, e->n_gid_map);
}

uid_t userns_uid(uid_t uid)
{
	UsernsEntry *e = userns_entry;

	if (!(root_ns_mask & CLONE_NEWUSER) || !e)
		return uid;

	return child_userns_xid(uid, e->uid_map, e->n_uid_map);
}

gid_t userns_gid(gid_t gid)
{
	UsernsEntry *e = userns_entry;

	if (!(root_ns_mask & CLONE_NEWUSER) || !e)
		return gid;

	return child_userns_xid(gid, e->gid_map, e->n_gid_map);
}

/* Convert uid from NS_ROOT down to its representation in NS_OTHER */
unsigned int target_userns_uid(struct ns_id *ns, unsigned int uid)
{
	if (!(root_ns_mask & CLONE_NEWUSER))
		return uid;
	if (ns == top_user_ns)
		return uid;
	/* User ns max nesting level is only 32 */
	uid = target_userns_uid(ns->parent, uid);
	return child_userns_xid(uid, ns->user.e->uid_map, ns->user.e->n_uid_map);
}

/* Convert gid from NS_ROOT down to its representation in NS_OTHER */
unsigned int target_userns_gid(struct ns_id *ns, unsigned int gid)
{
	if (!(root_ns_mask & CLONE_NEWUSER))
		return gid;
	if (ns == top_user_ns)
		return gid;
	/* User ns max nesting level is only 32 */
	gid = target_userns_gid(ns->parent, gid);
	return child_userns_xid(gid, ns->user.e->gid_map, ns->user.e->n_gid_map);
}

/* Convert uid from NS_OTHER ns up to its representation in NS_ROOT */
unsigned int root_userns_uid(struct ns_id *ns, unsigned int uid)
{
	if (!(root_ns_mask & CLONE_NEWUSER))
		return uid;
	while (ns != top_user_ns) {
		uid = parent_userns_uid(ns->user.e, uid);
		ns = ns->parent;
	}
	return uid;
}

/* Convert gid from NS_OTHER ns up to its representation in NS_ROOT */
unsigned int root_userns_gid(struct ns_id *ns, unsigned int gid)
{
	if (!(root_ns_mask & CLONE_NEWUSER))
		return gid;
	while (ns != top_user_ns) {
		gid = parent_userns_gid(ns->user.e, gid);
		ns = ns->parent;
	}
	return gid;
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
			if (ferror(f)) {
				pr_perror("Unable to parse extents: %d", ret);
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

static int __dump_user_ns(struct ns_id *ns);

static int dump_user_ns(void *arg)
{
	struct ns_id *ns = arg;

	if (switch_ns(ns->parent->ns_pid, &user_ns_desc, NULL) < 0) {
		pr_err("Can't enter user namespace\n");
		return -1;
	}

	return __dump_user_ns(ns);
}

int collect_user_ns(struct ns_id *ns, void *oarg)
{
	struct ns_id *p_ns;
	UsernsEntry *e;

	p_ns = ns->parent;

	e = xmalloc(sizeof(*e));
	if (!e)
		return -1;
	userns_entry__init(e);
	ns->user.e = e;
	if (ns->type == NS_ROOT) {
		userns_entry = e;
		top_user_ns = ns;
	}
	/*
	 * User namespace is dumped before files to get uid and gid
	 * mappings, which are used for convirting local id-s to
	 * userns id-s (userns_uid(), userns_gid())
	 */
	if (p_ns) {
		/*
		 * Currently, we are in NS_CRIU. To dump a NS_OTHER ns,
		 * we need to enter its parent ns. As entered to user_ns
		 * task has no a way back, we create a child for that.
		 * NS_ROOT is dumped w/o clone(), it's xids maps is relatively
		 * to NS_CRIU.
		 */
		return call_in_child_process(dump_user_ns, ns);
	} else {
		if (__dump_user_ns(ns))
			return -1;
	}

	return 0;
}

int collect_user_namespaces(bool for_dump)
{
	if (!for_dump)
		return 0;

	if (!(root_ns_mask & CLONE_NEWUSER))
		return 0;

	return walk_namespaces(&user_ns_desc, collect_user_ns, NULL);
}

static int collect_ns_hierarhy(bool for_dump)
{
	struct ns_id *ns;

	if (!for_dump)
		return 0;

	for (ns = ns_ids; ns != NULL; ns = ns->next) {
		if (ns->type == NS_CRIU)
			continue;
		if (set_ns_hookups(ns) < 0)
			return -1;
	}
	return 0;
}

static int check_user_ns(struct ns_id *ns)
{
	UsernsEntry *e = ns->user.e;
	pid_t pid = ns->ns_pid;
	int status;
	pid_t chld;

	if (ns->type != NS_ROOT)
		return 0;

	chld = fork();
	if (chld == -1) {
		pr_perror("Unable to fork a process");
		return -1;
	}

	if (chld == 0) {
		struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
		struct __user_cap_header_struct hdr;
		uid_t uid;
		gid_t gid;
		int i;

		uid = parent_userns_uid(e, 0);
		gid = parent_userns_gid(e, 0);
		if (uid == NS_INVALID_XID || gid == NS_INVALID_XID) {
			pr_err("Unable to convert uid or gid\n");
			return -1;
		}

		if (prctl(PR_SET_KEEPCAPS, 1)) {
			pr_perror("Unable to set PR_SET_KEEPCAPS");
			return -1;
		}

		if (setresgid(gid, gid, gid)) {
			pr_perror("Unable to set group ID");
			return -1;
		}

		if (setgroups(0, NULL) < 0) {
			pr_perror("Unable to drop supplementary groups");
			return -1;
		}

		if (setresuid(uid, uid, uid)) {
			pr_perror("Unable to set user ID");
			return -1;
		}

		hdr.version = _LINUX_CAPABILITY_VERSION_3;
		hdr.pid = 0;

		if (capget(&hdr, data) < 0) {
			pr_perror("capget");
			return -1;
		}
		data[0].effective = data[0].permitted;
		data[1].effective = data[1].permitted;
		if (capset(&hdr, data) < 0) {
			pr_perror("capset");
			return -1;
		}

		close_old_fds();
		for (i = SERVICE_FD_MIN + 1; i < SERVICE_FD_MAX; i++)
			close_service_fd(i);

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
		pr_perror("Unable to wait for PID %d", chld);
		return -1;
	}

	if (status) {
		pr_err("One or more namespaces doesn't belong to the target user namespace\n");
		return -1;
	}

	return 0;
}

static int __dump_user_ns(struct ns_id *ns)
{
	int ret, exit_code = -1;
	pid_t pid = ns->ns_pid;
	UsernsEntry *e = ns->user.e;

	ret = parse_id_map(pid, "uid_map", &e->uid_map);
	if (ret < 0)
		goto err;
	e->n_uid_map = ret;

	ret = parse_id_map(pid, "gid_map", &e->gid_map);
	if (ret < 0)
		goto err;
	e->n_gid_map = ret;

	if (check_user_ns(ns))
		return -1;

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

static int do_free_userns_map(struct ns_id *ns, void *arg)
{
	UsernsEntry *e = ns->user.e;

	if (!e)
		return 0;
	if (e->n_uid_map > 0) {
		xfree(e->uid_map[0]);
		xfree(e->uid_map);
	}
	if (e->n_gid_map > 0) {
		xfree(e->gid_map[0]);
		xfree(e->gid_map);
	}
	if (e == userns_entry)
		userns_entry = NULL;
	ns->user.e = NULL;

	return 0;
}
void free_userns_maps()
{
	walk_namespaces(&user_ns_desc, do_free_userns_map, NULL);
}

static int do_dump_namespaces(struct ns_id *ns)
{
	int ret;

	ret = switch_ns(ns->ns_pid, ns->nd, NULL);
	if (ret)
		return ret;

	switch (ns->nd->cflag) {
	case CLONE_NEWUTS:
		pr_info("Dump UTS namespace %d via %d\n",
				ns->id, ns->ns_pid);
		ret = dump_uts_ns(ns->id);
		break;
	case CLONE_NEWIPC:
		pr_info("Dump IPC namespace %d via %d\n",
				ns->id, ns->ns_pid);
		ret = dump_ipc_ns(ns->id);
		break;
	case CLONE_NEWNET:
		pr_info("Dump NET namespace info %d via %d\n",
				ns->id, ns->ns_pid);
		ret = dump_net_ns(ns);
		break;
	default:
		pr_err("Unknown namespace flag %x\n", ns->nd->cflag);
		break;
	}

	return ret;

}

int dump_namespaces(struct pstree_item *item, unsigned int ns_flags)
{
	struct pid *ns_pid = item->pid;
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

	pr_info("Dumping %d(%d)'s namespaces\n", ns_pid->ns[0].virt, ns_pid->real);

	if ((ns_flags & CLONE_NEWPID) && ns_pid->ns[0].virt != 1) {
		pr_err("Can't dump a pid namespace without the process init\n");
		return -1;
	}

	for (ns = ns_ids; ns; ns = ns->next) {
		/* Skip current namespaces, which are in the list too  */
		if (ns->type == NS_CRIU)
			continue;

		switch (ns->nd->cflag) {
			/* No data for pid namespaces to dump */
			case CLONE_NEWPID:
			/* Dumped explicitly with dump_mnt_namespaces() */
			case CLONE_NEWNS:
			/* Userns is dumped before dumping tasks */
			case CLONE_NEWUSER:
			/* handled separately in cgroup dumping code */
			case CLONE_NEWCGROUP:
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

	fd = get_service_fd(CR_PROC_FD_OFF);
	if (fd < 0)
		return -1;
	snprintf(buf, PAGE_SIZE, "%d/%s", pid, id_map);
	fd = openat(fd, buf, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", buf);
		return -1;
	}

	/*
	 *  We can perform only a single write (that may contain multiple
	 *  newline-delimited records) to a uid_map and a gid_map files.
	 */
	for (i = 0; i < n; i++)
		off += snprintf(buf + off, sizeof(buf) - off,
				"%u %u %u\n", extents[i]->first,
					extents[i]->lower_first,
					extents[i]->count);

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
	 * 2nd is the optional (NULL in response) arguments
	 */
	struct iovec iov[3];
	char c[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))];
};

int usernsd_pid;

static inline void unsc_msg_init(struct unsc_msg *m, uns_call_t *c,
		int *x, void *arg, size_t asize, int fd)
{
	struct cmsghdr *ch;
	struct ucred *ucred;

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

	m->h.msg_control = &m->c;

	/* Need to memzero because of:
	 * https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=514917
	 */
	memzero(&m->c, sizeof(m->c));

	m->h.msg_controllen = CMSG_SPACE(sizeof(struct ucred));

	ch = CMSG_FIRSTHDR(&m->h);
	ch->cmsg_len = CMSG_LEN(sizeof(struct ucred));
	ch->cmsg_level = SOL_SOCKET;
	ch->cmsg_type = SCM_CREDENTIALS;

	ucred = (struct ucred *) CMSG_DATA(ch);
	ucred->pid = getpid();
	ucred->uid = getuid();
	ucred->gid = getgid();

	if (fd >= 0) {
		m->h.msg_controllen += CMSG_SPACE(sizeof(int));
		ch = CMSG_NXTHDR(&m->h, ch);
		BUG_ON(!ch);
		ch->cmsg_len = CMSG_LEN(sizeof(int));
		ch->cmsg_level = SOL_SOCKET;
		ch->cmsg_type = SCM_RIGHTS;
		*((int *)CMSG_DATA(ch)) = fd;
	}
}

static void unsc_msg_pid_fd(struct unsc_msg *um, pid_t *pid, int *fd)
{
	struct cmsghdr *ch;
	struct ucred *ucred;

	ch = CMSG_FIRSTHDR(&um->h);
	BUG_ON(!ch);
	BUG_ON(ch->cmsg_len != CMSG_LEN(sizeof(struct ucred)));
	BUG_ON(ch->cmsg_level != SOL_SOCKET);
	BUG_ON(ch->cmsg_type != SCM_CREDENTIALS);

	if (pid) {
		ucred = (struct ucred *) CMSG_DATA(ch);
		*pid = ucred->pid;
	}

	ch = CMSG_NXTHDR(&um->h, ch);

	if (ch && ch->cmsg_len == CMSG_LEN(sizeof(int))) {
		BUG_ON(ch->cmsg_level != SOL_SOCKET);
		BUG_ON(ch->cmsg_type != SCM_RIGHTS);
		*fd = *((int *)CMSG_DATA(ch));
	} else {
		*fd = -1;
	}
}

void warn_if_pid_ns_helper_exited(pid_t real_pid)
{
	struct ns_id *ns;
	struct pid *pid;

	for (ns = ns_ids; ns; ns = ns->next) {
		if (ns->nd != &pid_ns_desc)
			continue;
		pid = __pstree_pid_by_virt(ns, ns->ns_pid);
		if (pid->real == real_pid) {
			pid->real = -1;
			break;
		}
	}

	if (ns)
		pr_err("Spurious pid ns helper: pid=%d\n", real_pid);
}

static int usernsd_recv_transport(void *arg, int fd, pid_t pid)
{
	if (install_service_fd(TRANSPORT_FD_OFF, fd) < 0) {
		pr_perror("Can't install transport fd\n");
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

int prep_usernsd_transport()
{
	struct sockaddr_un addr;
	int transport_fd, ret;
	socklen_t len;

	transport_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (transport_fd < 0) {
		pr_perror("Can't create transport socket");
		return -1;
	}

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, "x/criu-usernsd");
	len = SUN_LEN(&addr);
	*addr.sun_path = '\0';

	if (bind(transport_fd, (struct sockaddr *)&addr, len) < 0) {
		pr_perror("Can't bind transport sock");
		close(transport_fd);
		return -1;
	}
	ret = userns_call(usernsd_recv_transport, 0, NULL, 0, transport_fd);
	close(transport_fd);
	return ret;
}

static int usernsd(int sk)
{
	pr_info("uns: Daemon started\n");

	while (1) {
		struct unsc_msg um;
		static char msg[MAX_UNSFD_MSG_SIZE];
		uns_call_t call;
		int flags, fd, ret;
		pid_t pid;

		unsc_msg_init(&um, &call, &flags, msg, sizeof(msg), 0);
		if (recvmsg(sk, &um.h, 0) <= 0) {
			pr_perror("uns: recv req error");
			return -1;
		}

		unsc_msg_pid_fd(&um, &pid, &fd);
		pr_debug("uns: daemon calls %p (%d, %d, %x)\n", call, pid, fd, flags);

		/*
		 * Caller has sent us bare address of the routine it
		 * wants to call. Since the caller is fork()-ed from the
		 * same process as the daemon is, the latter has exactly
		 * the same code at exactly the same address as the
		 * former guy has. So go ahead and just call one!
		 */

		ret = call(msg, fd, pid);

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
				pr_err("uns: Async call failed. Exiting\n");
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
			pr_perror("uns: send resp error");
			return -1;
		}

		if (fd >= 0)
			close(fd);
	}
}

int __userns_call(const char *func_name, uns_call_t call, int flags,
		  void *arg, size_t arg_size, int fd)
{
	int ret, res, sk;
	bool async = flags & UNS_ASYNC;
	struct unsc_msg um;

	if (unlikely(arg_size > MAX_UNSFD_MSG_SIZE)) {
		pr_err("uns: message size exceeded\n");
		return -1;
	}

	if (!usernsd_pid)
		return call(arg, fd, getpid());

	sk = get_service_fd(USERNSD_SK);
	pr_debug("uns: calling %s (%d, %x)\n", func_name, fd, flags);

	if (!async)
		/*
		 * Why don't we lock for async requests? Because
		 * they just put the request in the daemon's
		 * queue and do not wait for the response. Thus
		 * when daemon response there's only one client
		 * waiting for it in recvmsg below, so he
		 * responses to proper caller.
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
		pr_perror("uns: send req error");
		ret = -1;
		goto out;
	}

	if (async) {
		ret = 0;
		goto out;
	}

	/* Get the response back */

	unsc_msg_init(&um, &call, &res, NULL, 0, 0);
	ret = recvmsg(sk, &um.h, 0);
	if (ret <= 0) {
		pr_perror("uns: recv resp error");
		ret = -1;
		goto out;
	}

	/* Decode the result and return */

	if (flags & UNS_FDOUT)
		unsc_msg_pid_fd(&um, NULL, &ret);
	else
		ret = res;
out:
	if (!async)
		mutex_unlock(&task_entries->userns_sync_lock);

	return ret;
}

static int start_usernsd(void)
{
	int sk[2];
	int one = 1;

	if (!(root_ns_mask & (CLONE_NEWUSER|CLONE_NEWPID)))
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
	 *    response.
	 */

	if (socketpair(PF_UNIX, SOCK_SEQPACKET, 0, sk)) {
		pr_perror("Can't make usernsd socket");
		return -1;
	}

	if (setsockopt(sk[0], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0) {
		pr_perror("failed to setsockopt");
		return -1;
	}

	if (setsockopt(sk[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof(1)) < 0) {
		pr_perror("failed to setsockopt");
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

static int exit_usernsd(void *arg, int fd, pid_t pid)
{
	int code = *(int *)arg;
	pr_info("uns: `- daemon exits w/ %d\n", code);
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
		sigprocmask(SIG_SETMASK, &oldmask, NULL);

		if (ret != 0)
			pr_err("uns: daemon exited abnormally\n");
		else
			pr_info("uns: daemon stopped\n");
	}

	return ret;
}

static int do_read_old_user_ns_img(struct ns_id *ns)
{
	struct cr_img *img;
	UsernsEntry *e;
	int ret;

	img = open_image(CR_FD_USERNS, O_RSTR, ns->id);
	if (!img)
		return -1;
	ret = pb_read_one(img, &e, PB_USERNS);
	close_image(img);
	if (ret < 0)
		return -1;
	ns->user.e = e;
	userns_entry = e;
	return 0;
}

static int read_old_user_ns_img(void)
{
	if (!(root_ns_mask & CLONE_NEWUSER))
		return 0;
	/* If new format img has already been read */
	if (top_user_ns->user.e)
		return 0;
	/* Old format img is only for top_user_ns */
	return do_read_old_user_ns_img(top_user_ns);
}

static int dump_ns_with_hookups(int for_dump)
{
	struct cr_img *img;
	struct ns_id *ns;
	int ret = 0;
	NsEntry e;

	if (!for_dump)
		return 0;

	img = open_image(CR_FD_NS, O_DUMP);
	if (!img)
		return -1;

	for (ns = ns_ids; ns != NULL; ns = ns->next) {
		if (ns->nd != &user_ns_desc &&
		    ns->nd != &pid_ns_desc &&
		    ns->nd != &net_ns_desc)
			continue;
		if (ns->type == NS_CRIU ||
		    !(root_ns_mask & ns->nd->cflag))
			continue;

		ns_entry__init(&e);
		e.id = ns->id;
		e.ns_cflag = ns->nd->cflag;

		if (ns->parent) {
			e.has_parent_id = true;
			e.parent_id = ns->parent->id;
		}
		if (ns->user_ns) {
			e.has_userns_id = true;
			e.userns_id = ns->user_ns->id;
		}
		if (ns->nd == &user_ns_desc) {
			e.user_ext = ns->user.e;
		}

		ret = pb_write_one(img, &e, PB_NS);
		if (ret < 0) {
			pr_err("Can't write ns.img\n");
			break;
		}
	}

	close_image(img);
	return ret;
}

struct delayed_ns {
	struct ns_id *ns;
	u32 userns_id;
	u32 parent_id;
};

int read_ns_with_hookups(void)
{
	struct ns_id *ns, *p_ns, *u_ns;
	struct delayed_ns *d_ns = NULL;
	NsEntry *e = NULL;
	int ret = 0, nr_d = 0;
	struct ns_desc *desc;
	struct cr_img *img;

	img = open_image(CR_FD_NS, O_RSTR);
	if (!img)
		return -1;
	if (empty_image(img))
		goto close;

	while (1) {
		ret = pb_read_one_eof(img, &e, PB_NS);
		if (ret <= 0)
			goto close;
		ret = -1;
		desc = &pid_ns_desc;
		if (e->ns_cflag == CLONE_NEWUSER)
			desc = &user_ns_desc;
		else if (e->ns_cflag == CLONE_NEWNET)
			desc = &net_ns_desc;

		ns = rst_new_ns_id(e->id, -1, desc, NS_OTHER);
		if (!ns) {
			pr_err("Can't find ns %d\n", e->id);
			goto close;
		}

		if (e->user_ext && e->ns_cflag == CLONE_NEWUSER) {
			ns->user.e = dup_userns_entry(e->user_ext);
			if (!ns->user.e) {
				pr_err("Can't dup map\n");
				goto close;
			}
		}

		if (e->has_userns_id) {
			if (e->ns_cflag == CLONE_NEWUSER) {
				pr_err("Unexpected user_ns\n");
				goto close;
			}
			u_ns = lookup_ns_by_id(e->userns_id, &user_ns_desc);
			if (!u_ns) {
				/* User_ns hasn't read yet; set aside this ns */
				d_ns = xrealloc(d_ns, (nr_d + 1) * sizeof(*d_ns));
				if (!d_ns)
					goto close;
				d_ns[nr_d].ns = ns;
				d_ns[nr_d].parent_id = 0;
				d_ns[nr_d++].userns_id = e->userns_id;
			} else
				ns->user_ns = u_ns;
		}

		if (e->has_parent_id) {
			if (!(e->ns_cflag & (CLONE_NEWUSER|CLONE_NEWPID))) {
				pr_err("Unexpected parent\n");
				goto close;
			}
			p_ns = lookup_ns_by_id(e->parent_id, desc);
			if (!p_ns) {
				/* Parent ns may hasn't been read yet */
				if (!nr_d || d_ns[nr_d-1].ns != ns) {
					d_ns = xrealloc(d_ns, (nr_d + 1) * sizeof(*d_ns));
					if (!d_ns)
						goto close;
					d_ns[nr_d].ns = ns;
					d_ns[nr_d++].userns_id = 0;
				}
				d_ns[nr_d-1].parent_id = e->parent_id;
			} else {
				ns->parent = p_ns;
				list_add(&ns->siblings, &p_ns->children);
			}
		} else if (e->ns_cflag == CLONE_NEWUSER) {
			if (top_user_ns) {
				pr_err("top_user_ns already set\n");
				goto close;
			}
			ns->type = NS_ROOT;
			top_user_ns = ns;
			userns_entry = ns->user.e;
		} else if (e->ns_cflag == CLONE_NEWPID) {
			if (top_pid_ns) {
				pr_err("top_pid_ns already set\n");
				goto close;
			}
			ns->type = NS_ROOT;
			top_pid_ns = ns;
		}

		ns_entry__free_unpacked(e, NULL);
	}
close:
	if (!ret) {
		while (nr_d-- > 0) {
			if (d_ns[nr_d].userns_id > 0) {
				u_ns = lookup_ns_by_id(d_ns[nr_d].userns_id, &user_ns_desc);
				if (!u_ns) {
					pr_err("Can't find user_ns: %d\n", d_ns[nr_d].userns_id);
					ret = -1;
					break;
				}
				d_ns[nr_d].ns->user_ns = u_ns;
			}
			if (d_ns[nr_d].parent_id > 0) {
				p_ns = lookup_ns_by_id(d_ns[nr_d].parent_id, d_ns[nr_d].ns->nd);
				if (!p_ns) {
					pr_err("Can't find parent\n");
					ret = -1;
					break;
				}
				d_ns[nr_d].ns->parent = p_ns;
				list_add(&d_ns[nr_d].ns->siblings, &p_ns->children);
			}
		}
	}
	if (ret)
		pr_err("Failed to read ns image\n");
	xfree(d_ns);
	close_image(img);
	return ret;
}

static int mark_root_ns(uint32_t id, struct ns_desc *desc, struct ns_id **ns_ret)
{
	struct ns_id *ns;

	ns = lookup_ns_by_id(id, desc);
	if (!ns) {
		pr_err("Can't find root ns %u, %s\n", id, desc->str);
		return -1;
	}
	ns->type = NS_ROOT;

	if (ns_ret)
		*ns_ret = ns;

	return 0;
}

#define MARK_ROOT_NS(ids, name, ns)	\
	(ids->has_##name##_ns_id && mark_root_ns(ids->name##_ns_id, &name##_ns_desc, ns) < 0)

int set_ns_roots(void)
{
	TaskKobjIdsEntry *ids = root_item->ids;
	struct ns_id *ns;

	/* Set root for all namespaces except user and pid, which are set in read_ns_with_hookups() */
	if (MARK_ROOT_NS(ids, net, &top_net_ns) || MARK_ROOT_NS(ids, ipc, NULL) ||
	    MARK_ROOT_NS(ids, uts, NULL) || MARK_ROOT_NS(ids, mnt, NULL) ||
	    MARK_ROOT_NS(ids, cgroup, NULL))
		return -1;
	if (!top_user_ns) {
		/*
		 * In old dumps or if !(root_ns_mask & CLONE_NEWUSER),
		 * ns.img does not exist/contain user_ns.
		 */
		if (MARK_ROOT_NS(ids, user, &top_user_ns))
			return -1;
	}

	/* Populate !(root_ns_mask & CLONE_NEWXXX) namespaces and fixup old dumps */
	for (ns = ns_ids; ns != NULL; ns = ns->next)
		if (ns->user_ns == NULL && ns->nd != &user_ns_desc)
			ns->user_ns = top_user_ns;

	return 0;
}

int prepare_userns(pid_t real_pid, UsernsEntry *e)
{
	if (write_id_map(real_pid, e->uid_map, e->n_uid_map, "uid_map"))
		return -1;

	if (write_id_map(real_pid, e->gid_map, e->n_gid_map, "gid_map"))
		return -1;

	return 0;
}

int collect_namespaces(bool for_dump)
{
	int ret;

	ret = collect_ns_hierarhy(for_dump);
	if (ret < 0)
		return ret;

	ret = collect_user_namespaces(for_dump);
	if (ret < 0)
		return ret;

	ret = collect_mnt_namespaces(for_dump);
	if (ret < 0)
		return ret;

	ret = collect_net_namespaces(for_dump);
	if (ret < 0)
		return ret;

	ret = dump_ns_with_hookups(for_dump);
	if (ret < 0)
		return ret;

	return 0;
}

int prepare_userns_creds(void)
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
		return -1;
	}

	return 0;
}

static int get_join_ns_fd(struct join_ns *jn)
{
	int pid, fd;
	char nsf[32];
	char *pnsf;

	pid = atoi(jn->ns_file);
	if (pid > 0) {
		snprintf(nsf, sizeof(nsf), "/proc/%d/ns/%s", pid, jn->nd->str);
		pnsf = nsf;
	} else {
		pnsf = jn->ns_file;
	}

	fd = open(pnsf, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open ns file %s", pnsf);
		return -1;
	}
	jn->ns_fd = fd;
	return 0;
}

static int switch_join_ns(struct join_ns *jn)
{
	struct stat st, self_st;
	char buf[32];

	if (jn->nd == &user_ns_desc) {
		/* It is not permitted to use setns() to reenter the caller's current
		 * user namespace.  This prevents a caller that has dropped capabilities
		 * from regaining those capabilities via a call to setns()
		 */
		if (fstat(jn->ns_fd, &st) == -1) {
			pr_perror("Can't get ns file %s stat", jn->ns_file);
			return -1;
		}

		snprintf(buf, sizeof(buf), "/proc/self/ns/%s", jn->nd->str);
		if (stat(buf, &self_st) == -1) {
			pr_perror("Can't get ns file %s stat", buf);
			return -1;
		}

		if (st.st_ino == self_st.st_ino)
			return 0;
	}

	if (setns(jn->ns_fd, jn->nd->cflag)) {
		pr_perror("Failed to setns when join-ns %s:%s", jn->nd->str, jn->ns_file);
		return -1;
	}

	return 0;
}

static int switch_user_join_ns(struct join_ns *jn)
{
	uid_t uid;
	gid_t gid;

	if (jn == NULL)
		return 0;

	if (switch_join_ns(jn))
		return -1;

	if (jn->extra_opts.user_extra.uid == NULL)
		uid = getuid();
	else
		uid = atoi(jn->extra_opts.user_extra.uid);

	if (jn->extra_opts.user_extra.gid == NULL)
		gid = getgid();
	else
		gid = atoi(jn->extra_opts.user_extra.gid);

	/* FIXME:
	 * if err occurs in setuid/setgid, should we just alert or
	 * return an error
	 */
	if (setuid(uid)) {
		pr_perror("setuid failed while joining userns");
		return -1;
	}
	if (setgid(gid)) {
		pr_perror("setgid failed while joining userns");
		return -1;
	}

	return 0;
}

int join_namespaces(void)
{
	struct join_ns *jn, *user_jn = NULL;
	int ret = -1;

	list_for_each_entry(jn, &opts.join_ns, list)
		if (get_join_ns_fd(jn))
			goto err_out;

	list_for_each_entry(jn, &opts.join_ns, list)
		if (jn->nd == &user_ns_desc) {
			user_jn = jn;
		} else {
			if (switch_join_ns(jn))
				goto err_out;
		}

	if (switch_user_join_ns(user_jn))
		goto err_out;

	ret = 0;
err_out:
	list_for_each_entry(jn, &opts.join_ns, list)
		close_safe(&jn->ns_fd);
	return ret;
}

int store_self_ns(struct ns_id *ns)
{
	int fd, id;

	/* Pin one with a file descriptor */
	fd = open_proc(PROC_SELF, "ns/%s", ns->nd->str);
	if (fd < 0)
		return -1;

	id = fdstore_add(fd);
	close(fd);
	return id;
}

enum {
	NS__CREATED = 1,
	NS__MAPS_POPULATED,
	NS__RESTORED,
	NS__EXIT_HELPER,
	NS__ERROR,
};

struct ns_arg {
	struct ns_id *me;
	futex_t futex;
	pid_t pid;
};

static int create_user_ns_hierarhy_fn(void *in_arg)
{
	struct ns_arg *arg, *p_arg = in_arg;
	futex_t *p_futex = NULL, *futex = NULL;
	size_t map_size = 2 * 1024 * 1024;
	void *map = MAP_FAILED, *stack;
	int status, ret = -1;
	struct ns_id *me, *child;
	pid_t pid = -1;

	if (p_arg->me != top_user_ns)
		p_futex = &p_arg->futex;
	me = p_arg->me;

	me->user.nsfd_id = store_self_ns(me);
	if (me->user.nsfd_id < 0) {
		pr_err("Can't add fd to fdstore\n");
		goto out;
	}

	if (p_futex) {
		/* Set self pid to allow parent restore user_ns maps */
		p_arg->pid = get_self_real_pid();
		futex_set_and_wake(p_futex, NS__CREATED);

		futex_wait_while_lt(p_futex, NS__MAPS_POPULATED);
		if (prepare_userns_creds()) {
			pr_err("Can't prepare creds\n");
			goto out;
		}
	}

	map = mmap(NULL, map_size, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (map == MAP_FAILED) {
		pr_perror("Failed to mmap");
		goto out;
	}
	arg = map + map_size - sizeof(*arg);
	stack = ((void *)arg) - sizeof(unsigned long);
	futex = &arg->futex;

	list_for_each_entry(child, &me->children, siblings) {
		arg->me = child;
		futex_init(futex);

		pid = clone(create_user_ns_hierarhy_fn, stack, CLONE_NEWUSER | CLONE_VM | CLONE_FILES | SIGCHLD, arg);
		if (pid < 0) {
			pr_perror("Can't clone");
			goto out;
		}
		futex_wait_while_lt(futex, NS__CREATED);
		/* Use child real pid */
		if (prepare_userns(arg->pid, child->user.e) < 0) {
			pr_err("Can't prepare child user_ns\n");
			goto out;
		}
		futex_set_and_wake(futex, NS__MAPS_POPULATED);

		errno = 0;
		if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) {
			pr_perror("Child process waiting: %d", status);
			close_pid_proc();
			goto out;
		}
		close_pid_proc();
	}

	ret = 0;
out:
	if (p_futex)
		futex_set_and_wake(p_futex, ret ? NS__ERROR : NS__RESTORED);
	if (map != MAP_FAILED)
		munmap(map, map_size);
	return ret ? 1 : 0;
}

static int create_user_ns_hierarhy(void)
{
	struct ns_arg arg = { .me = top_user_ns };
	return create_user_ns_hierarhy_fn(&arg);
}

int prepare_namespace(struct pstree_item *item, unsigned long clone_flags)
{
	pid_t pid = vpid(item);
	sigset_t sig_mask;
	int id, ret = -1;

	pr_info("Restoring namespaces %d flags 0x%lx\n",
			vpid(item), clone_flags);

	if (block_sigmask(&sig_mask, SIGCHLD) < 0)
		return -1;

	if ((clone_flags & CLONE_NEWUSER) && (prepare_userns_creds() ||
					      create_user_ns_hierarhy()))
		goto out;

	/*
	 * On netns restore we launch an IP tool, thus we
	 * have to restore it _before_ altering the mount
	 * tree (i.e. -- mnt_ns restoring)
	 */

	id = ns_per_id ? item->ids->uts_ns_id : pid;
	if ((clone_flags & CLONE_NEWUTS) && prepare_utsns(id))
		goto out;
	id = ns_per_id ? item->ids->ipc_ns_id : pid;
	if ((clone_flags & CLONE_NEWIPC) && prepare_ipc_ns(id))
		goto out;

	if (prepare_net_namespaces())
		goto out;

	/*
	 * This one is special -- there can be several mount
	 * namespaces and prepare_mnt_ns handles them itself.
	 */
	if (prepare_mnt_ns())
		goto out;

	ret = 0;
out:
	if (restore_sigmask(&sig_mask) < 0)
		ret = -1;

	return ret;
}

int prepare_namespace_before_tasks(void)
{
	if (start_usernsd())
		goto err_unds;

	if (netns_keep_nsfd())
		goto err_netns;

	if (mntns_maybe_create_roots())
		goto err_mnt;

	if (read_mnt_ns_img())
		goto err_img;

	if (read_old_user_ns_img())
		goto err_img;

	return 0;

err_img:
	cleanup_mnt_ns();
err_mnt:
	/*
	 * Nothing, netns' descriptor will be closed
	 * on criu exit
	 */
err_netns:
	stop_usernsd();
err_unds:
	return -1;
}

int __set_user_ns(struct ns_id *ns)
{
	if (!(root_ns_mask & CLONE_NEWUSER))
		return 0;

	if (current->user_ns && current->user_ns->id == ns->id)
		return 0;

	if (setns_from_fdstore(ns->user.nsfd_id, CLONE_NEWUSER))
		return -1;

	current->user_ns = ns;

	if (prepare_userns_creds() < 0) {
		pr_err("Can't set creds\n");
		return -1;
	}
	return 0;
}

int set_user_ns(u32 id)
{
	struct ns_id *ns;

	if (current->user_ns && current->user_ns->id == id)
		return 0;

	ns = lookup_ns_by_id(id, &user_ns_desc);
	if (!ns) {
		pr_err("Can't find user_ns %u\n", id);
		return -1;
	}
	return __set_user_ns(ns);
}

static int do_reserve_pid_ns_helpers(struct ns_id *ns, void *oarg)
{
	struct pstree_item *helper;
	pid_t pid[MAX_NS_NESTING], *p;
	int level;

	level = get_free_pids(ns, pid);
	if (level <= 0)
		return -1;

	p = &pid[MAX_NS_NESTING - level];
	helper = lookup_create_item(p, level, ns->id);
	if (helper == NULL)
		return -1;
	ns->ns_pid = pid[MAX_NS_NESTING-1];
	return 0;
}

int reserve_pid_ns_helpers(void)
{
	if (!(root_ns_mask & CLONE_NEWPID))
		return 0;

	return walk_namespaces(&pid_ns_desc, do_reserve_pid_ns_helpers, NULL);
}

static int pid_ns_helper_sock(struct ns_id *ns)
{
	struct sockaddr_un addr;
	socklen_t len;
	int sk;

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("Can't create helper socket");
		return -1;
	}
	pid_ns_helper_socket_name(&addr, &len, ns->id);

	if (bind(sk, (struct sockaddr *)&addr, len) < 0) {
		pr_perror("Can't bind pid_ns sock");
		close(sk);
		return -1;
	}

	return sk;
}

static int pid_ns_helper(struct ns_id *ns, int sk)
{
	struct sockaddr_un addr;
	struct msghdr msg = {0};
	struct iovec iov;
	pid_t pid;

	msg.msg_name = &addr;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	while (1) {
		int answer = 0;
		msg.msg_namelen = sizeof(addr);
		iov.iov_base = &pid;
		iov.iov_len = sizeof(pid);

		if (recvmsg(sk, &msg, 0) < 0) {
			pr_perror("recv() failed to read pid");
			break;
		}

		if (__set_next_pid(pid) < 0) {
			pr_err("Can't set next pid\n");
			answer = -1;
		}

		iov.iov_base = &answer;
		iov.iov_len = sizeof(answer);
		if (sendmsg(sk, &msg, 0) < 0) {
			pr_perror("Can't send answer");
			break;
		}
	}

	return -1;
}

static int do_create_pid_ns_helper(void *arg, int sk, pid_t unused_pid)
{
	int pid_ns_fd, i, transport_fd, saved_errno, ret = -1;
	struct pstree_item *ns_reaper;
	struct ns_id *ns, *tmp;
	struct pid *pid;
	pid_t child;

	ns_reaper = *(struct pstree_item **)arg;
	ns = lookup_ns_by_id(ns_reaper->ids->pid_ns_id, &pid_ns_desc);

	pid = __pstree_pid_by_virt(ns, ns->ns_pid);
	if (!pid) {
		pr_err("Can't find helper reserved pid\n");
		goto close_sk;
	}

	if (switch_ns(ns_reaper->pid->real, &pid_ns_desc, &pid_ns_fd) < 0)
		goto close_sk;

	lock_last_pid();

	transport_fd = get_service_fd(TRANSPORT_FD_OFF);
	BUG_ON(transport_fd < 0);
	/*
	 * Starting not from pid->level - 1, as it's helper has not created yet
	 * (we're creating it in the moment), and the true pid for this level
	 * is set by the task, who does close(CLONE_NEWPID) (this task is sender of fd).
	 */
	for (i = pid->level - 2, tmp = ns->parent; i >= 0; i--, tmp = tmp->parent)
		if (request_set_next_pid(tmp->id, pid->ns[i].virt, transport_fd)) {
			unlock_last_pid();
			goto restore_ns;
		}
	child = sys_clone_unified(CLONE_PARENT|SIGCHLD, NULL, NULL, NULL, 0);
	if (!child)
		exit(pid_ns_helper(ns, sk));
	saved_errno = errno;
	unlock_last_pid();
	if (child < 0) {
		errno = saved_errno;
		pr_perror("Can't fork");
		goto restore_ns;
	}
	futex_set_and_wake(&ns->pid.helper_created, 1);
	pid->real = child;

	ret = 0;
restore_ns:
	if (restore_ns(pid_ns_fd, &pid_ns_desc) < 0)
		ret = -1;
close_sk:
	close_safe(&sk);
	return ret;
}

/*
 * Task may set last_pid only for its active pid namespace,
 * so if NSpid of a child contains more then one level, we
 * need external help to populate the whole pid hierarhy
 * (pid in parent pid_ns, pid in grand parent etc). Pid ns
 * helpers are used for that.
 *
 * We need a task or tasks to be a parent of pid_ns helpers.
 * To live in common hierarhy and to be a TASK_HELPER is not
 * possible, because it introduces circular dependencies.
 * The same is to be children of criu main task, because
 * we already have dependencies between it and root_item
 * (NO more dependencies!). So, we choose usernsd for that:
 * it always exists and have command interface.
 */
int create_pid_ns_helper(struct ns_id *ns)
{
	int sk;

	BUG_ON(getpid() != INIT_PID);
	BUG_ON(ns->parent && !futex_get(&ns->parent->pid.helper_created));

	if (__set_next_pid(ns->ns_pid) < 0) {
		pr_err("Can't set next fd\n");
		return -1;
	}

	sk = pid_ns_helper_sock(ns);
	if (sk < 0)
		return -1;

	if (userns_call(do_create_pid_ns_helper, 0, &current, sizeof(current), sk) < 0) {
		pr_err("Can't create pid_ns helper\n");
		close(sk);
		return -1;
	}
	close(sk);
	return 0;
}

static int do_destroy_pid_ns_helpers(void)
{
	int status, sig_blocked = true, ret = 0;
	sigset_t sig_mask;
	struct ns_id *ns;
	struct pid *pid;

	if (block_sigmask(&sig_mask, SIGCHLD)) {
		sig_blocked = false;
		ret = -1;
	}

	for (ns = ns_ids; ns; ns = ns->next) {
		if (ns->nd != &pid_ns_desc)
			continue;
		pid = __pstree_pid_by_virt(ns, ns->ns_pid);
		if (!pid) {
			pr_err("Can't find pid_ns helper\n");
			ret = -1;
			continue;
		}
		if (pid->real <= 0)
			continue;

		if (kill(pid->real, SIGKILL) < 0) {
			pr_perror("Can't kill\n");
			ret = -1;
			continue;
		}

		if (waitpid(pid->real, &status, 0) != pid->real) {
			pr_perror("Error during waiting pid_ns helper");
			ret = -1;
			continue;
		}
		pid->real = -1;
	}

	if (sig_blocked && restore_sigmask(&sig_mask))
		ret = -1;

	return ret;
}

int destroy_pid_ns_helpers(void)
{
	if (!(root_ns_mask & CLONE_NEWPID))
		return 0;

	return do_destroy_pid_ns_helpers();
}

int __setns_from_fdstore(int fd_id, int nstype, const char *file, int line)
{
	int fd, saved_errno, ret;

	fd = fdstore_get(fd_id);
	if (fd < 0)
		goto err;

	ret = setns(fd, nstype);
	saved_errno = errno;
	close(fd);
	if (ret) {
		errno = saved_errno;
		pr_perror("Can't set user ns");
		goto err;
	}

	return 0;
err:
	pr_err("Can't set %s_ns from fdstore (called from %s: %d)\n",
		ns_to_string(nstype), file, line);
	return -1;
}



struct ns_desc pid_ns_desc = NS_DESC_ENTRY(CLONE_NEWPID, "pid", "pid_for_children");
struct ns_desc user_ns_desc = NS_DESC_ENTRY(CLONE_NEWUSER, "user", NULL);
