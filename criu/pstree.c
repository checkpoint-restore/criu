#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>

#include "types.h"
#include "cr_options.h"
#include "pstree.h"
#include "rst-malloc.h"
#include "common/lock.h"
#include "namespaces.h"
#include "cgroup.h"
#include "ipc_ns.h"
#include "uts_ns.h"
#include "files.h"
#include "tty.h"
#include "mount.h"
#include "dump.h"
#include "util.h"
#include "net.h"

#include "protobuf.h"
#include "images/pstree.pb-c.h"
#include "crtools.h"

struct pstree_item *root_item;

void core_entry_free(CoreEntry *core)
{
	if (core->tc && core->tc->timers)
		xfree(core->tc->timers->posix);
	if (core->thread_core)
		xfree(core->thread_core->creds->groups);
	arch_free_thread_info(core);
	xfree(core);
}

#ifndef RLIM_NLIMITS
# define RLIM_NLIMITS 16
#endif

CoreEntry *core_entry_alloc(int th, int tsk)
{
	size_t sz;
	CoreEntry *core = NULL;
	void *m;

	sz = sizeof(CoreEntry);
	if (tsk) {
		sz += sizeof(TaskCoreEntry) + TASK_COMM_LEN;
		if (th) {
			sz += sizeof(TaskRlimitsEntry);
			sz += RLIM_NLIMITS * sizeof(RlimitEntry *);
			sz += RLIM_NLIMITS * sizeof(RlimitEntry);
			sz += sizeof(TaskTimersEntry);
			sz += 3 * sizeof(ItimerEntry); /* 3 for real, virt and prof */
		}
	}
	if (th) {
		CredsEntry *ce = NULL;

		sz += sizeof(ThreadCoreEntry) + sizeof(ThreadSasEntry) + sizeof(CredsEntry);

		sz += CR_CAP_SIZE * sizeof(ce->cap_inh[0]);
		sz += CR_CAP_SIZE * sizeof(ce->cap_prm[0]);
		sz += CR_CAP_SIZE * sizeof(ce->cap_eff[0]);
		sz += CR_CAP_SIZE * sizeof(ce->cap_bnd[0]);
		/*
		 * @groups are dynamic and allocated
		 * on demand.
		 */
	}

	m = xmalloc(sz);
	if (m) {
		core = xptr_pull(&m, CoreEntry);
		core_entry__init(core);
		core->mtype = CORE_ENTRY__MARCH;

		if (tsk) {
			core->tc = xptr_pull(&m, TaskCoreEntry);
			task_core_entry__init(core->tc);
			core->tc->comm = xptr_pull_s(&m, TASK_COMM_LEN);
			memzero(core->tc->comm, TASK_COMM_LEN);

			if (th) {
				TaskRlimitsEntry *rls;
				TaskTimersEntry *tte;
				int i;

				rls = core->tc->rlimits = xptr_pull(&m, TaskRlimitsEntry);
				task_rlimits_entry__init(rls);

				rls->n_rlimits = RLIM_NLIMITS;
				rls->rlimits = xptr_pull_s(&m, sizeof(RlimitEntry *) * RLIM_NLIMITS);

				for (i = 0; i < RLIM_NLIMITS; i++) {
					rls->rlimits[i] = xptr_pull(&m, RlimitEntry);
					rlimit_entry__init(rls->rlimits[i]);
				}

				tte = core->tc->timers = xptr_pull(&m, TaskTimersEntry);
				task_timers_entry__init(tte);
				tte->real = xptr_pull(&m, ItimerEntry);
				itimer_entry__init(tte->real);
				tte->virt = xptr_pull(&m, ItimerEntry);
				itimer_entry__init(tte->virt);
				tte->prof = xptr_pull(&m, ItimerEntry);
				itimer_entry__init(tte->prof);
			}
		}

		if (th) {
			CredsEntry *ce;

			core->thread_core = xptr_pull(&m, ThreadCoreEntry);
			thread_core_entry__init(core->thread_core);
			core->thread_core->sas = xptr_pull(&m, ThreadSasEntry);
			thread_sas_entry__init(core->thread_core->sas);
			ce = core->thread_core->creds = xptr_pull(&m, CredsEntry);
			creds_entry__init(ce);

			ce->n_cap_inh	= CR_CAP_SIZE;
			ce->n_cap_prm	= CR_CAP_SIZE;
			ce->n_cap_eff	= CR_CAP_SIZE;
			ce->n_cap_bnd	= CR_CAP_SIZE;
			ce->cap_inh	= xptr_pull_s(&m, CR_CAP_SIZE * sizeof(ce->cap_inh[0]));
			ce->cap_prm	= xptr_pull_s(&m, CR_CAP_SIZE * sizeof(ce->cap_prm[0]));
			ce->cap_eff	= xptr_pull_s(&m, CR_CAP_SIZE * sizeof(ce->cap_eff[0]));
			ce->cap_bnd	= xptr_pull_s(&m, CR_CAP_SIZE * sizeof(ce->cap_bnd[0]));

			if (arch_alloc_thread_info(core)) {
				xfree(core);
				core = NULL;
			}
		}
	}

	return core;
}

int pstree_alloc_cores(struct pstree_item *item)
{
	unsigned int i;

	item->core = xzalloc(sizeof(*item->core) * item->nr_threads);
	if (!item->core)
		return -1;

	for (i = 0; i < item->nr_threads; i++) {
		if (item->threads[i]->real == item->pid->real)
			item->core[i] = core_entry_alloc(1, 1);
		else
			item->core[i] = core_entry_alloc(1, 0);

		if (!item->core[i])
			goto err;
	}

	return 0;
err:
	pstree_free_cores(item);
	return -1;
}

void pstree_free_cores(struct pstree_item *item)
{
	unsigned int i;

	if (item->core) {
		for (i = 1; i < item->nr_threads; i++)
			if (item->core[i])
				core_entry_free(item->core[i]);
		xfree(item->core);
		item->core = NULL;
	}
}

void free_pstree_item(struct pstree_item *item)
{
	pstree_free_cores(item);
	xfree(item->threads);
	xfree(item->pid);
	xfree(item->pgid);
	xfree(item->sid);
	xfree(item);
}

void free_pstree(struct pstree_item *root_item)
{
	struct pstree_item *item = root_item, *parent;

	while (item) {
		if (!list_empty(&item->children)) {
			item = list_first_entry(&item->children, struct pstree_item, sibling);
			continue;
		}

		parent = item->parent;
		list_del(&item->sibling);
		free_pstree_item(item);
		item = parent;
	}
}

struct pstree_item *__alloc_pstree_item(bool rst, int level)
{
	struct pstree_item *item;
	int sz, p_sz;

	p_sz = PID_SIZE(level);
	if (!rst) {
		sz = sizeof(*item) + sizeof(struct dmp_info);
		item = xzalloc(sz);
		if (!item)
			return NULL;
		item->pid = xmalloc(p_sz);
		item->pgid = xmalloc(p_sz);
		item->sid = xmalloc(p_sz);
		if (!item->pid || !item->pgid || !item->sid) {
			free_pstree_item(item);
			return NULL;
		}
	} else {
		sz = sizeof(*item) + sizeof(struct rst_info);
		item = shmalloc(sz);
		if (!item)
			return NULL;
		memset(item, 0, sz);
		vm_area_list_init(&rsti(item)->vmas);
		INIT_LIST_HEAD(&rsti(item)->vma_io);

		/*
		 * On restore we never expand pid level,
		 * so allocate them all at once.
		 */
		item->pid = shmalloc(3 * p_sz);
		if (!item->pid) {
			shfree_last(item);
			return NULL;
		}
		item->pgid = (void *)item->pid + p_sz;
		item->sid = (void *)item->pgid + p_sz;
	}

	INIT_LIST_HEAD(&item->children);
	INIT_LIST_HEAD(&item->sibling);

	vpid(item) = -1;
	item->pid->real = -1;
	item->pid->state = TASK_UNDEF;
	item->born_sid = -1;
	item->pid->item = item;
	futex_init(&item->task_st);
	item->pid->level = item->sid->level = item->pgid->level = level;

	return item;
}

void add_child_task(struct pstree_item *child, struct pstree_item *parent)
{
	struct pstree_item *item;

	if (vpid(child) != INIT_PID)
		list_add_tail(&child->sibling, &parent->children);
	else {
		list_for_each_entry(item, &parent->children, sibling)
			if (vpid(item) != INIT_PID ||
			    item->pid->level >= child->pid->level)
				break;
		/* Add child before item */
		list_add_tail(&child->sibling, &item->sibling);
	}
}

void move_child_task(struct pstree_item *child, struct pstree_item *new_parent)
{
	list_del(&child->sibling);
	add_child_task(child, new_parent);
}

int init_pstree_helper(struct pstree_item *ret)
{
	BUG_ON(!ret->parent);
	ret->pid->state = TASK_HELPER;
	rsti(ret)->clone_flags = CLONE_FILES | CLONE_FS;
	if (shared_fdt_prepare(ret) < 0)
		return -1;
	task_entries->nr_helpers++;
	return 0;
}

/* Search only root's subtree, possibly skipping descendants */
struct pstree_item *pssubtree_item_next(struct pstree_item *item,
		struct pstree_item *root, bool skip_descendants)
{
	if (!skip_descendants && !list_empty(&item->children))
		return list_first_entry(&item->children, struct pstree_item, sibling);

	while (item->parent && item != root) {
		if (item->sibling.next != &item->parent->children)
			return list_entry(item->sibling.next, struct pstree_item, sibling);
		item = item->parent;
	}

	return NULL;
}

/* Deep first search on children */
struct pstree_item *pstree_item_next(struct pstree_item *item)
{
	return pssubtree_item_next(item, NULL, false);
}

/* Preorder traversal of pstree item */
int preorder_pstree_traversal(struct pstree_item *item, int (*f)(struct pstree_item *))
{
	struct pstree_item *cursor;

	if (f(item) < 0)
		return -1;

	list_for_each_entry(cursor, &item->children, sibling) {
		if (preorder_pstree_traversal(cursor, f) < 0)
			return -1;
	}

	return 0;
}

static void free_pstree_entry(PstreeEntry *e)
{
	int i;

	xfree(e->ns_pid);
	xfree(e->ns_pgid);
	xfree(e->ns_sid);

	if (e->tids) {
		for (i = 0; i < e->n_tids; i++) {
			if (e->tids[i]) {
				xfree(e->tids[i]->tid);
				xfree(e->tids[i]);
			}
		}
		xfree(e->tids);
	}
}

static int plant_ns_xid(uint32_t **ns_xid, size_t *n_ns_xid, int level, struct pid *xid)
{
	int i;

	*ns_xid = xmalloc(level * sizeof(uint32_t));
	if (!*ns_xid)
		return -1;
	for (i = 0; i < level; i++)
			(*ns_xid)[i] = xid->ns[i].virt;
	*n_ns_xid = level;
	return 0;
}

int is_session_leader(struct pstree_item *item)
{
	if (vsid(item) == vpid(item)) {
		BUG_ON(!equal_pid(item->pid, item->sid));
		return 1;
	}
	return 0;
}

int dump_pstree(struct pstree_item *root_item)
{
	struct pstree_item *item = root_item;
	PstreeEntry e = PSTREE_ENTRY__INIT;
	int ret = -1, i, level;
	struct cr_img *img;

	pr_info("\n");
	pr_info("Dumping pstree (pid: %d)\n", root_item->pid->real);
	pr_info("----------------------------------------\n");

	/*
	 * Make sure we're dumping session leader, if not an
	 * appropriate option must be passed.
	 *
	 * Also note that if we're not a session leader we
	 * can't get the situation where the leader sits somewhere
	 * deeper in process tree, thus top-level checking for
	 * leader is enough.
	 */
	if (!is_session_leader(root_item)) {
		if (!opts.shell_job) {
			pr_err("The root process %d is not a session leader. "
			       "Consider using --" OPT_SHELL_JOB " option\n", vpid(item));
			return -1;
		}
	}

	img = open_image(CR_FD_PSTREE, O_DUMP);
	if (!img)
		return -1;

	for_each_pstree_item(item) {
		pr_info("Process: %d(%d)\n", vpid(item), item->pid->real);
		level = item->pid->level;

		e.ppid		= item->parent ? vpid(item->parent) : 0;

		if (plant_ns_xid(&e.ns_pid,  &e.n_ns_pid,  level, item->pid)  < 0 ||
		    plant_ns_xid(&e.ns_pgid, &e.n_ns_pgid, level, item->pgid) < 0 ||
		    plant_ns_xid(&e.ns_sid,  &e.n_ns_sid,  level, item->sid)  < 0)
			goto err;
		e.n_tids	= item->nr_threads;
		if (e.n_tids) {
			e.tids	= xzalloc(e.n_tids * sizeof(NsTid *));
			if (!e.tids)
				goto err;
			for (i = 0; i < e.n_tids; i++) {
				e.tids[i] = xzalloc(sizeof(NsTid));
				if (!e.tids[i])
					goto err;
				ns_tid__init(e.tids[i]);
				e.tids[i]->n_tid = level;
				if (plant_ns_xid(&e.tids[i]->tid, &e.tids[i]->n_tid,
						 level, item->threads[i])  < 0)
					goto err;
			}
		}
		ret = pb_write_one(img, &e, PB_PSTREE);
		if (ret)
			goto err;
		free_pstree_entry(&e);
		pstree_entry__init(&e);
	}
	ret = 0;

err:
	pr_info("----------------------------------------\n");
	free_pstree_entry(&e);
	close_image(img);
	return ret;
}

static int prepare_pstree_for_shell_job(void)
{
	pid_t current_sid = getsid(getpid());
	pid_t current_gid = getpgid(getpid());

	struct pstree_item *pi;

	pid_t old_sid;
	pid_t old_gid;

	if (!opts.shell_job)
		return 0;

	if (is_session_leader(root_item))
		return 0;

	/*
	 * Migration of a root task group leader is a bit tricky.
	 * When a task yields SIGSTOP, the kernel notifies the parent
	 * with SIGCHLD. This means when task is running in a
	 * shell, the shell obtains SIGCHLD and sends a task to
	 * the background.
	 *
	 * The situation gets changed once we restore the
	 * program -- our tool become an additional stub between
	 * the restored program and the shell. So to be able to
	 * notify the shell with SIGCHLD from our restored
	 * program -- we make the root task to inherit the
	 * process group from us.
	 *
	 * Not that clever solution but at least it works.
	 */

	old_sid = vsid(root_item);
	old_gid = vpgid(root_item);

	pr_info("Migrating process tree (GID %d->%d SID %d->%d)\n",
		old_gid, current_gid, old_sid, current_sid);

	for_each_pstree_item(pi) {
		if (vpgid(pi) == old_gid)
			vpgid(pi) = current_gid;
		if (vsid(pi) == old_sid)
			vsid(pi) = current_sid;
	}

	if (lookup_create_item(&current_sid, 1, root_item->ids->pid_ns_id) == NULL)
		return -1;
	if (lookup_create_item(&current_gid, 1, root_item->ids->pid_ns_id) == NULL)
		return -1;

	return 0;
}

static struct pid *find_pid_or_place_in_hier(struct rb_node **root, pid_t pid, int level,
					     struct rb_node **ret_parent, struct rb_node ***ret_place)
{
	struct rb_node *node = *root;
	struct rb_node **new = root;
	struct rb_node *parent = NULL;

	while (node) {
		struct pid *this = rb_entry(node, struct pid, ns[level].node);

		parent = *new;
		if (pid < this->ns[level].virt)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (pid > this->ns[level].virt)
			node = node->rb_right, new = &((*new)->rb_right);
		else
			return this;
	}
	*ret_parent = parent;
	*ret_place = new;
	return NULL;
}

/*
 * Try to find a pid node in the tree and insert a new one,
 * it is not there yet. If pid_node isn't set, pstree_item
 * is inserted.
 */
static struct pid *lookup_create_pid(pid_t *pid, int level, struct pid *pid_node, int ns_id)
{
	struct rb_node **new = NULL, *parent = NULL;
	int i, orig_level = level;
	struct pid *found;
	struct ns_id *ns;

	ns = lookup_ns_by_id(ns_id, &pid_ns_desc);

	while (level > 0 && ns && !pid[level-1]) {
		level--;
		ns = ns->parent;
	}
	if (!level || !ns) {
		pr_err("Can't skip zero pids levels (%d) or find {parent,} ns (%d)\n", level, ns_id);
		return NULL;
	}

	found = find_pid_or_place_in_hier(&ns->pid.rb_root.rb_node, pid[level-1], level-1, &parent, &new);
	if (found) {
		for (i = level - 2; i >= 0; i--)
			if (pid[i] != found->ns[i].virt || RB_EMPTY_NODE(&found->ns[i].node)) {
				pr_err("Wrong pid\n");
				return NULL;
			}
		return found;
	}

	if (!pid_node) {
		struct pstree_item *item;

		item = __alloc_pstree_item(true, orig_level);
		if (item == NULL)
			return NULL;

		for (i = 0; i < orig_level; i++)
			item->pid->ns[i].virt = pid[i];
		pid_node = item->pid;
	}

	for (i = level-1; i >= 0; i--) {
		found = find_pid_or_place_in_hier(&ns->pid.rb_root.rb_node, pid[i], i, &parent, &new);
		if (found) {
			pr_err("pid is already linked\n");
			return NULL;
		}
		if (!pid[i]) {
			pr_err("Zero pid level\n");
			return NULL;
		}
		rb_link_and_balance(&ns->pid.rb_root, &pid_node->ns[i].node, parent, new);
		ns = ns->parent;
		if (!ns && i) {
			pr_err("ns has no parent\n");
			return NULL;
		}
	}
	return pid_node;
}

void pstree_insert_pid(struct pid *pid_node, uint32_t ns_id)
{
	struct pid* n;
	pid_t pid[MAX_NS_NESTING];
	int i;

	BUG_ON(pid_node->level > MAX_NS_NESTING);
	for (i = 0; i < pid_node->level; i++)
		pid[i] = pid_node->ns[i].virt;

	n = lookup_create_pid(pid, pid_node->level, pid_node, ns_id);

	BUG_ON(n != pid_node);
}

struct pstree_item *lookup_create_item(pid_t *pid, int level, uint32_t ns_id)
{
	struct pid *node;;

	node = lookup_create_pid(pid, level, NULL, ns_id);
	if (!node)
		return NULL;
	BUG_ON(node->state == TASK_THREAD);

	return node->item;
}

struct pid *__pstree_pid_by_virt(struct ns_id *ns, pid_t pid)
{
	struct rb_node *node = ns->pid.rb_root.rb_node;
	struct ns_id *i = ns;
	int level = 0;

	while ((i = i->parent) != NULL)
		level++;

	while (node) {
		struct pid *this = rb_entry(node, struct pid, ns[level].node);

		if (pid < this->ns[level].virt)
			node = node->rb_left;
		else if (pid > this->ns[level].virt)
			node = node->rb_right;
		else
			return this;
	}
	return NULL;
}

int fixup_pid_for_children_ns(TaskKobjIdsEntry *ids)
{
	if (!ids->has_pid_for_children_ns_id) {
		ids->has_pid_for_children_ns_id = true;
		ids->pid_for_children_ns_id = ids->pid_ns_id;
	} else if (!lookup_ns_by_id(ids->pid_for_children_ns_id, &pid_ns_desc)) {
		pr_err("Can't find pid_for_children ns linked\n");
		return -1;
	}
	return 0;
}

static int read_pstree_ids(pid_t pid, TaskKobjIdsEntry **ids)
{
	struct cr_img *img;
	int ret;

	img = open_image(CR_FD_IDS, O_RSTR, pid);
	if (!img)
		return -1;

	ret = pb_read_one_eof(img, ids, PB_IDS);
	close_image(img);

	if (ret <= 0)
		return ret;
	ret = 0;
#define ADD_OR_COPY_ID(ids, name)								\
	if (!ret) {										\
		if ((*ids)->has_##name##_ns_id)							\
			ret = rst_add_ns_id((*ids)->name##_ns_id, pid, &name##_ns_desc);	\
		else if (root_item && root_item->ids && root_item->ids->has_##name##_ns_id) {	\
			(*ids)->has_##name##_ns_id = true;					\
			(*ids)->name##_ns_id = root_item->ids->name##_ns_id;			\
		}										\
	}
	ADD_OR_COPY_ID(ids, mnt);
	ADD_OR_COPY_ID(ids, net);
	ADD_OR_COPY_ID(ids, user);
	ADD_OR_COPY_ID(ids, pid);
	ADD_OR_COPY_ID(ids, ipc);
	ADD_OR_COPY_ID(ids, uts);
	ADD_OR_COPY_ID(ids, cgroup);
#undef ADD_OR_COPY_ID

	if (!ret && (!(*ids)->has_pid_ns_id || !(*ids)->has_net_ns_id ||
		     !(*ids)->ipc_ns_id || !(*ids)->uts_ns_id || !(*ids)->mnt_ns_id)) {
			/*
			 * At least root_item must have the fields,
			 * implemented before the img format became
			 * stable (commit 2105e18eee70).
			 */
			pr_err("No task ids or always dumped ns ids\n");
			ret = -1;
	}

	if (!ret)
		ret = fixup_pid_for_children_ns(*ids);

	if (!ret && !top_pid_ns) {
		/*
		 * If top_pid_ns is not set, this means that here is old dump,
		 * which does not contain ns.img. It can have only one pid_ns,
		 * so we set it here.
		 */
		top_pid_ns = lookup_ns_by_id((*ids)->pid_ns_id, &pid_ns_desc);
	}

	return ret;
}

static int read_one_pstree(struct cr_img *img, PstreeEntry **ret_e)
{
	PstreeEntry *e;
	int i, ret;

	ret = pb_read_one_eof(img, ret_e, PB_PSTREE);
	if (ret <= 0)
		return ret;
	e = *ret_e;
	if ((!e->has_pid && !e->n_ns_pid) || (!e->has_pgid && !e->n_ns_pgid) ||
	    (!e->has_sid && !e->n_ns_sid) || (e->n_threads && e->n_tids))
		goto err;
	/* Assign ns_pid, ns_pgid and ns_sid if here is old format image */
#define ASSIGN_NSXID_IF_NEED(name, source)		\
	if (!e->n_##name) {				\
		e->n_##name = 1;			\
		e->name = xmalloc(sizeof(uint32_t));	\
		if (!e->name)				\
			goto err;			\
		e->name[0] = e->source;			\
	}
	ASSIGN_NSXID_IF_NEED(ns_pid, pid);
	ASSIGN_NSXID_IF_NEED(ns_pgid, pgid);
	ASSIGN_NSXID_IF_NEED(ns_sid, sid);
#undef ASSIGN_NSXID_IF_NEED

	/* Assign tids if here is old format image */
	if (!e->n_tids) {
		e->n_tids = e->n_threads;
		e->tids = xzalloc(e->n_tids * sizeof(NsTid *));
		if (!e->tids)
			goto err;
		for (i = 0; i < e->n_tids; i++) {
			e->tids[i] = xzalloc(sizeof(NsTid));
			if (!e->tids[i])
				goto err;
			ns_tid__init(e->tids[i]);
			e->tids[i]->n_tid = 1;
			e->tids[i]->tid = xmalloc(sizeof(uint32_t));
			if (!e->tids[i]->tid)
				goto err;
			e->tids[i]->tid[0] = e->threads[i];
		}
	}

	return 1;
err:
	pr_err("Error of reading pstree\n");
	return -1;
}

static int read_pstree_image(pid_t *pid_max)
{
	struct pstree_item *pi, *parent;
	TaskKobjIdsEntry *ids;
	int ret = 0, i, k;
	struct cr_img *img;
	struct pid *pid;

	pr_info("Reading image tree\n");

	img = open_image(CR_FD_PSTREE, O_RSTR);
	if (!img)
		return -1;

	while (1) {
		PstreeEntry *e;

		ret = read_one_pstree(img, &e);
		if (ret <= 0)
			break;

		ret = read_pstree_ids(e->ns_pid[0], &ids);
		if (ret < 0)
			break;

		ret = -1;

		parent = NULL;
		if (e->ppid) {
			pid = pstree_pid_by_virt(e->ppid);
			if (!pid || pid->state == TASK_UNDEF || pid->state == TASK_THREAD) {
				pr_err("Can't find a parent for %d\n", e->ns_pid[0]);
				pstree_entry__free_unpacked(e, NULL);
				break;
			}
			parent = pid->item;
		}

		if (!ids) {
			/* In not corrupted old image, only dead tasks don't have ids */
			if (!parent || !parent->ids) {
				pr_err("No root_item or its ids\n");
				break;
			}
			ids = parent->ids;
		}

		pi = lookup_create_item((pid_t *)e->ns_pid, e->n_ns_pid, ids->pid_ns_id);
		if (pi == NULL)
			break;
		BUG_ON(pi->pid->state != TASK_UNDEF);

		pi->ids = ids;

		/*
		 * All pids should be added in the tree to be able to find
		 * free pid-s for helpers. pstree_item for these pid-s will
		 * be initialized when we meet PstreeEntry with this pid or
		 * we will create helpers for them.
		 */
		if (lookup_create_item((pid_t *)e->ns_pgid, e->n_ns_pgid, ids->pid_ns_id) == NULL)
			break;
		if (lookup_create_item((pid_t *)e->ns_sid, e->n_ns_sid, ids->pid_ns_id) == NULL)
			break;

		BUG_ON(vpid(pi) != e->ns_pid[0]);
		if (e->ns_pid[0] > *pid_max)
			*pid_max = e->ns_pid[0];
		for (i = 0; i < pi->pgid->level; i++)
			pi->pgid->ns[i].virt = e->ns_pgid[i];
		if (e->ns_pgid[0] > *pid_max)
			*pid_max = e->ns_pgid[0];
		for (i = 0; i < pi->sid->level; i++)
			pi->sid->ns[i].virt = e->ns_sid[i];
		if (e->ns_sid[0] > *pid_max)
			*pid_max = e->ns_sid[0];
		pi->pid->state = TASK_ALIVE;

		if (!parent) {
			if (root_item) {
				pr_err("Parent missed on non-root task "
				       "with pid %d, image corruption!\n", e->ns_pid[0]);
				goto err;
			}
			root_item = pi;
			pi->parent = NULL;
		} else {
			pi->parent = parent;
			add_child_task(pi, parent);
		}

		pi->nr_threads = e->n_tids;
		pi->threads = xzalloc(e->n_tids * sizeof(struct pid *));
		if (!pi->threads)
			break;

		for (i = 0; i < e->n_tids; i++) {
			struct pid *node;
			pi->threads[i] = xmalloc(sizeof(struct pid) + (pi->pid->level-1) * sizeof(node->ns[0]));
			if (!pi->threads)
				goto err;
			pi->threads[i]->real = -1;
			pi->threads[i]->level = pi->pid->level;
			for (k = 0; k < pi->pid->level; k++)
				pi->threads[i]->ns[k].virt = e->tids[i]->tid[k];
			pi->threads[i]->state = TASK_THREAD;
			pi->threads[i]->item = NULL;
			if (i == 0)
				continue; /* A thread leader is in a tree already */
			node = lookup_create_pid((pid_t *)e->tids[i]->tid, e->tids[i]->n_tid, pi->threads[i], ids->pid_ns_id);

			BUG_ON(node == NULL);
			if (node != pi->threads[i]) {
				pr_err("Unexpected task %d in a tree %d\n", e->tids[i]->tid[0], i);
				return -1;
			}
		}

		task_entries->nr_threads += e->n_tids;
		task_entries->nr_tasks++;

		pstree_entry__free_unpacked(e, NULL);
	}

	if (ret == 0)
		ret = set_ns_roots();
err:
	close_image(img);
	return ret;
}

#define RESERVED_PIDS		300
static int get_free_pid(struct ns_id *ns)
{
	struct pid *prev, *next;
	struct ns_id *i = ns;
	int level = 0;

	while ((i = i->parent) != NULL)
		level++;

	prev = rb_entry(rb_first(&ns->pid.rb_root), struct pid, ns[level].node);

	while (1) {
		struct rb_node *node;
		pid_t pid;

		pid = prev->ns[level].virt + 1;
		pid = pid < RESERVED_PIDS ? RESERVED_PIDS + 1 : pid;

		node = rb_next(&prev->ns[level].node);
		if (node == NULL)
			return pid;
		next = rb_entry(node, struct pid, ns[level].node);
		if (next->ns[level].virt > pid)
			return pid;
		prev = next;
	}

	return -1;
}

int get_free_pids(struct ns_id *ns, pid_t *pids)
{
	int i;

	for (i = MAX_NS_NESTING-1; ns && i >= 0; i--, ns = ns->parent) {
		pids[i] = get_free_pid(ns);
		if (pids[i] < 0) {
			pr_err("Can't find free pid\n");
			return -1;
		}
	}

	if (ns) {
		pr_err("Too many pids levels\n");
		return -1;
	}

	return MAX_NS_NESTING - i - 1;
}

static int can_inherit_sid(struct pstree_item *item)
{
	struct pstree_item *parent;
	parent = item->parent;
	while (parent) {
		/* parent will give the right sid to item */
		if (vsid(item) == vsid(parent))
			return 1;
		/* non-leader can't give children sid different from it's own */
		if (!is_session_leader(parent))
			break;
		/* some other ancestor can have the right pid for item */
		parent = parent->parent;
	}
	return 0;
}

static struct pstree_item *get_helper(int sid, unsigned int id, struct list_head *helpers)
{
	struct pstree_item *helper;
	list_for_each_entry(helper, helpers, sibling)
		if (vsid(helper) == sid && helper->ids->pid_ns_id == id)
			return helper;
	return NULL;
}

static int handle_init_reparent(struct ns_id *ns, void *oarg)
{
	struct pstree_item *init, *item, *helper, *branch, *tmp;
	LIST_HEAD(helpers);

	init = __pstree_item_by_virt(ns, INIT_PID);

	for_each_pssubtree_item(item, init) {
skip:
		if (!item)
			break;

		/* Skip pidns's reaper */
		if (item == init)
			continue;

		/* Session leaders do setsid() */
		if (is_session_leader(item)) {
			/*
			 * Stop on pidns init, it's descendants
			 * will be handled from it's pidns.
			 */
			if (last_level_pid(item->pid) == INIT_PID)
				goto skip_descendants;
			continue;
		}

		if (can_inherit_sid(item))
			goto skip_descendants;

		helper = get_helper(vsid(item), ns->id, &helpers);
		if (!helper) {
			struct pstree_item *leader;
			pid_t pid[MAX_NS_NESTING];
			int level;

			leader = pstree_item_by_virt(vsid(item));
			BUG_ON(leader == NULL);

			if (leader->pid->level > init->pid->level)
				/*
				 * If leader is in lower pidns, then item's branch
				 * couldn't have been reparented to init from leader
				 * - will manage item in other pidns
				 *
				 * FIXME One tricky case which does not fit these rule
				 * is doing CLONE_PARENT after entering pidns and setsid.
				 */
				goto skip_descendants;

			if (leader->pid->state == TASK_UNDEF) {
				struct ns_id *leader_pid_ns = ns;
				struct pstree_item *linit;
				int i;

				/*
				 * Search a proper pidns where session leader helper
				 * can be created (using the fact that all processes
				 * of some session should be in pidns of leader or
				 * some ancestor pidns)
				 */
				for (i = 0; i < init->pid->level - leader->pid->level; i++) {
					BUG_ON(!leader_pid_ns->parent);
					leader_pid_ns = leader_pid_ns->parent;
				}
				BUG_ON(!leader_pid_ns);
				linit = __pstree_item_by_virt(leader_pid_ns, INIT_PID);
				BUG_ON(!linit);

				pr_info("Add a session leader helper %d\n", vsid(item));

				memcpy(leader->sid, item->sid, PID_SIZE(leader->sid->level));
				memcpy(leader->pgid, item->sid, PID_SIZE(leader->pgid->level));
				leader->ids = linit->ids;
				leader->parent = linit;

				add_child_task(leader, leader->parent);
				init_pstree_helper(leader);
			}
			BUG_ON(!is_session_leader(leader));

			level = get_free_pids(ns, pid);
			if (level <= 0)
				return -1;

			helper = lookup_create_item(&pid[MAX_NS_NESTING - level], level, ns->id);
			if (helper == NULL)
				return -1;

			memcpy(helper->sid, item->sid, PID_SIZE(helper->sid->level));
			memcpy(helper->pgid, leader->pgid, PID_SIZE(leader->pgid->level));
			helper->ids = init->ids;
			helper->parent = leader;

			list_add_tail(&helper->sibling, &helpers);
			init_pstree_helper(helper);

			pr_info("Add a helper %d for restoring SID %d\n", vpid(helper), vsid(helper));
		}

		branch = item;
		while (branch->parent && branch->parent != init)
			branch = branch->parent;
		pr_info("Attach %d to the temporary task %d\n", vpid(branch), vpid(helper));

		if (branch->sibling.next == &init->children)
			/* Last child of init */
			item = NULL;
		else
			/* Skip the subtree that we're reparenting to helper */
			item = list_entry(branch->sibling.next, struct pstree_item, sibling);

		/* Re-reparent branch */
		branch->parent = helper;
		move_child_task(branch, helper);
		goto skip;
skip_descendants:
		/* Descendants of non-leader should be fine, skip them */
		item = pssubtree_item_next(item, init, true);
		goto skip;
	}

	list_for_each_entry_safe(helper, tmp, &helpers, sibling) {
		move_child_task(helper, helper->parent);
		pr_info("Attach helper %d to the task %d\n", vpid(helper), vpid(helper->parent));
	}
	return 0;
}

static int prepare_pstree_ids(void)
{
	struct pstree_item *item, *helper;
	pid_t current_pgid = getpgid(getpid());

	if (!list_empty(&top_pid_ns->children))
		return 0;

	/*
	 * Some task can be reparented to init. A helper task should be added
	 * for restoring sid of such tasks. The helper tasks will be exited
	 * immediately after forking children and all children will be
	 * reparented to init.
	 */
	if (walk_namespaces(&pid_ns_desc, handle_init_reparent, NULL))
		return -1;

	for_each_pstree_item(item) {
		if (!item->parent) /* skip the root task */
			continue;

		if (item->pid->state == TASK_HELPER)
			continue;

		if (!is_session_leader(item)) {
			struct pstree_item *parent;

			/* Lookup the leader, it could fork a child before and after setsid() */
			parent = item->parent;
			while (parent) {
				/* Found leader */
				if (equal_pid(parent->pid, item->sid))
					break;

				/* Inherited sid from parent */
				if (equal_pid(parent->sid, item->sid)) {
					parent = parent->parent;
					continue;
				}

				/* Non-leader parent has different sid */
				if (!is_session_leader(parent)) {
					pr_err("Can't find a session leader for %d\n", vsid(item));
					return -1;
				}

				if (parent->born_sid != -1 && parent->born_sid != vsid(item)) {
					pr_err("Can't figure out which sid (%d or %d)"
						"the process %d was born with\n",
						parent->born_sid, vsid(item), vpid(parent));
					return -1;
				}
				parent->born_sid = vsid(item);
				pr_info("%d was born with sid %d\n", vpid(parent), vsid(item));
				parent = parent->parent;
			}

			if (parent == NULL) {
				pr_err("Can't find a session leader for %d\n", vsid(item));
				return -1;
			}
		}
	}

	/* Add a process group leader if it is absent  */
	for_each_pstree_item(item) {
		struct pid *pid;

		if (!item->pgid || equal_pid(item->pid, item->pgid))
			continue;

		pid = pstree_pid_by_virt(vpgid(item));
		if (pid->state != TASK_UNDEF) {
			BUG_ON(pid->state == TASK_THREAD);
			rsti(item)->pgrp_leader = pid->item;
			continue;
		}

		/*
		 * If the PGID is eq to current one -- this
		 * means we're inheriting group from the current
		 * task so we need to escape creating a helper here.
		 */
		if (current_pgid == vpgid(item))
			continue;

		helper = pid->item;

		vsid(helper) = vsid(item);
		vpgid(helper) = vpgid(item);
		vpid(helper) = vpgid(item);
		helper->parent = item;
		helper->ids = item->ids;
		if (init_pstree_helper(helper)) {
			pr_err("Can't init helper\n");
			return -1;
		}
		add_child_task(helper, item);
		rsti(item)->pgrp_leader = helper;

		pr_info("Add a helper %d for restoring PGID %d\n",
				vpid(helper), vpgid(helper));
	}

	return 0;
}

static unsigned long get_clone_mask(TaskKobjIdsEntry *i,
		TaskKobjIdsEntry *p)
{
	unsigned long mask = 0;

	if (i->files_id == p->files_id)
		mask |= CLONE_FILES;
	if (i->pid_ns_id != p->pid_ns_id)
		mask |= CLONE_NEWPID;
	if (i->net_ns_id != p->net_ns_id)
		mask |= CLONE_NEWNET;
	if (i->ipc_ns_id != p->ipc_ns_id)
		mask |= CLONE_NEWIPC;
	if (i->uts_ns_id != p->uts_ns_id)
		mask |= CLONE_NEWUTS;
	if (i->mnt_ns_id != p->mnt_ns_id)
		mask |= CLONE_NEWNS;
	if (i->user_ns_id != p->user_ns_id)
		mask |= CLONE_NEWUSER;

	return mask;
}

static int prepare_pstree_kobj_ids(void)
{
	struct pstree_item *item;

	/* Find a process with minimal pid for shared fd tables */
	for_each_pstree_item(item) {
		struct pstree_item *parent = item->parent;
		TaskKobjIdsEntry *ids;
		unsigned long cflags;

		if (parent)
			ids = parent->ids;
		else
			ids = root_ids;

		/*
		 * Add some sanity check on image data.
		 */
		if (unlikely(!ids)) {
			pr_err("No kIDs provided, image corruption\n");
			return -1;
		}

		cflags = get_clone_mask(item->ids, ids);

		if (cflags & CLONE_FILES) {
			int ret;

			/*
			 * There might be a case when kIDs for
			 * root task are the same as in root_ids,
			 * thus it's image corruption and we should
			 * exit out.
			 */
			if (unlikely(!item->parent)) {
				pr_err("Image corruption on kIDs data\n");
				return -1;
			}

			ret = shared_fdt_prepare(item);
			if (ret)
				return ret;
		}

		rsti(item)->clone_flags = cflags;
		if (parent)
			/*
			 * Mount namespaces are setns()-ed at
			 * restore_task_mnt_ns() explicitly,
			 * no need in creating it with its own
			 * temporary namespace.
			 *
			 * Root task is exceptional -- it will
			 * be born in a fresh new mount namespace
			 * which will be populated with all other
			 * namespaces' entries.
			 *
			 * User namespaces are created in create_ns_hierarhy()
			 * before the tasks, as their hierarhy does not correlated
			 * with tasks hierarhy in any way.
			 */
			rsti(item)->clone_flags &= ~(CLONE_NEWNS | CLONE_NEWUSER);
		/*
		 * Net namespaces also do not correlated with task hierarhy,
		 * so we create them manually in prepare_net_namespaces().
		 * The second reason is that some kernel modules, such as network
		 * packet generator, run kernel thread upon net-namespace creattion
		 * taking the pid we've been requeting via LAST_PID_PATH interface
		 * in fork_with_pid(), so that we can't restore a take with pid needed.
		 *
		 * The cgroup namespace is also unshared explicitly in the
		 * move_in_cgroup(), so drop this flag here as well.
		 */
		rsti(item)->clone_flags &= ~(CLONE_NEWNET | CLONE_NEWCGROUP);
		if (last_level_pid(item->pid) != INIT_PID)
			rsti(item)->clone_flags &= ~CLONE_NEWPID;

		cflags &= CLONE_ALLNS;

		if (item == root_item) {
			pr_info("Will restore in %lx namespaces\n", cflags);
			root_ns_mask = cflags;
		} else if (cflags & ~(root_ns_mask & CLONE_SUBNS)) {
			/*
			 * Namespaces from CLONE_SUBNS can be nested, but in
			 * this case nobody can't share external namespaces of
			 * these types.
			 *
			 * Workaround for all other namespaces --
			 * all tasks should be in one namespace. And
			 * this namespace is either inherited from the
			 * criu or is created for the init task (only)
			 */
			pr_err("Can't restore sub-task in NS\n");
			return -1;
		}
	}

	pr_debug("NS mask to use %lx\n", root_ns_mask);
	return 0;
}

int prepare_pstree(void)
{
	int ret;
	pid_t pid_max = 0, kpid_max = 0;
	int fd;
	char buf[21];

	fd = open_proc(PROC_GEN, PID_MAX_PATH);
	if (fd >= 0) {
		ret = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (ret > 0) {
			buf[ret] = 0;
			kpid_max = strtoul(buf, NULL, 10);
			pr_debug("kernel pid_max=%d\n", kpid_max);
		}
	}

	ret = read_pstree_image(&pid_max);
	pr_debug("pstree pid_max=%d\n", pid_max);

	if (!ret && kpid_max && pid_max > kpid_max) {
		/* Try to set kernel pid_max */
		fd = open_proc_rw(PROC_GEN, PID_MAX_PATH);
		if (fd == -1)
			ret = -1;
		else {
			snprintf(buf, sizeof(buf), "%u", pid_max+1);
			if (write(fd, buf, strlen(buf)) < 0) {
				pr_perror("Can't set kernel pid_max=%s", buf);
				ret = -1;
			}
			else
				pr_info("kernel pid_max pushed to %s\n", buf);
			close(fd);
		}
	}

	if (!ret)
		/*
		 * Shell job may inherit sid/pgid from the current
		 * shell, not from image. Set things up for this.
		 */
		ret = prepare_pstree_for_shell_job();
	if (!ret)
		/*
		 * Walk the collected tree and prepare for restoring
		 * of shared objects at clone time
		 */
		ret = prepare_pstree_kobj_ids();
	if (!ret)
		/*
		 * Session/Group leaders might be dead. Need to fix
		 * pstree with properly injected helper tasks.
		 */
		ret = prepare_pstree_ids();
	if (!ret)
		ret = reserve_pid_ns_helpers();

	return ret;
}

int prepare_dummy_pstree(void)
{
	pid_t dummy = 0;

	if (check_img_inventory() == -1)
		return -1;

	if (prepare_task_entries() == -1)
		return -1;

	if (read_pstree_image(&dummy) == -1)
		return -1;

	return 0;
}

bool restore_before_setsid(struct pstree_item *child)
{
	int csid = child->born_sid == -1 ? vsid(child) : child->born_sid;

	if (!list_empty(&top_pid_ns->children))
		return false;

	if (child->parent->born_sid == csid)
		return true;

	return false;
}

struct pstree_item *__pstree_item_by_virt(struct ns_id *ns, pid_t virt)
{
	struct pid *pid;

	pid = __pstree_pid_by_virt(ns, virt);
	if (pid == NULL)
		return NULL;
	BUG_ON(pid->state == TASK_THREAD);

	return pid->item;
}

struct pstree_item *pstree_item_by_real(pid_t real)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		if (item->pid->real == real)
			return item;
	}
	return NULL;
}

int pid_to_virt(pid_t real)
{
	struct pstree_item *item;

	item = pstree_item_by_real(real);
	if (item)
		return vpid(item);
	return 0;
}
