#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>

#include "cr_options.h"
#include "pstree.h"
#include "util.h"
#include "lock.h"
#include "namespaces.h"
#include "files.h"
#include "tty.h"
#include "mount.h"
#include "asm/dump.h"

#include "protobuf.h"
#include "protobuf/pstree.pb-c.h"

struct pstree_item *root_item;

void core_entry_free(CoreEntry *core)
{
	if (core->tc && core->tc->timers)
		xfree(core->tc->timers->posix);
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
	if (th)
		sz += sizeof(ThreadCoreEntry) + sizeof(ThreadSasEntry);

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
			core->thread_core = xptr_pull(&m, ThreadCoreEntry);
			thread_core_entry__init(core->thread_core);
			core->thread_core->sas = xptr_pull(&m, ThreadSasEntry);
			thread_sas_entry__init(core->thread_core->sas);

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
		if (item->threads[i].real == item->pid.real)
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
			core_entry_free(item->core[i]);
		xfree(item->core);
		item->core = NULL;
	}
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
		pstree_free_cores(item);
		xfree(item->threads);
		xfree(item);
		item = parent;
	}
}

struct pstree_item *__alloc_pstree_item(bool rst)
{
	struct pstree_item *item;

	if (!rst) {
		item = xzalloc(sizeof(*item));
		if (!item)
			return NULL;
	} else {
		item = shmalloc(sizeof(*item) + sizeof(item->rst[0]));
		if (!item)
			return NULL;
		memset(item, 0, sizeof(*item) + sizeof(item->rst[0]));
		vm_area_list_init(&item->rst[0].vmas);
	}

	INIT_LIST_HEAD(&item->children);
	INIT_LIST_HEAD(&item->sibling);

	item->pid.virt = -1;
	item->pid.real = -1;
	item->born_sid = -1;

	return item;
}

/* Deep first search on children */
struct pstree_item *pstree_item_next(struct pstree_item *item)
{
	if (!list_empty(&item->children))
		return list_first_entry(&item->children, struct pstree_item, sibling);

	while (item->parent) {
		if (item->sibling.next != &item->parent->children)
			return list_entry(item->sibling.next, struct pstree_item, sibling);
		item = item->parent;
	}

	return NULL;
}

int dump_pstree(struct pstree_item *root_item)
{
	struct pstree_item *item = root_item;
	PstreeEntry e = PSTREE_ENTRY__INIT;
	int ret = -1, i;
	int pstree_fd;

	pr_info("\n");
	pr_info("Dumping pstree (pid: %d)\n", root_item->pid.real);
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
	if (root_item->pid.virt != root_item->sid) {
		if (!opts.shell_job) {
			pr_err("The root process %d is not a session leader. "
			       "Consider using --" OPT_SHELL_JOB " option\n", item->pid.virt);
			return -1;
		}
	}

	pstree_fd = open_image(CR_FD_PSTREE, O_DUMP);
	if (pstree_fd < 0)
		return -1;

	for_each_pstree_item(item) {
		pr_info("Process: %d(%d)\n", item->pid.virt, item->pid.real);

		e.pid		= item->pid.virt;
		e.ppid		= item->parent ? item->parent->pid.virt : 0;
		e.pgid		= item->pgid;
		e.sid		= item->sid;
		e.n_threads	= item->nr_threads;

		e.threads = xmalloc(sizeof(e.threads[0]) * e.n_threads);
		if (!e.threads)
			goto err;

		for (i = 0; i < item->nr_threads; i++)
			e.threads[i] = item->threads[i].virt;

		ret = pb_write_one(pstree_fd, &e, PB_PSTREE);
		xfree(e.threads);

		if (ret)
			goto err;
	}
	ret = 0;

err:
	pr_info("----------------------------------------\n");
	close(pstree_fd);
	return ret;
}

static int max_pid = 0;

static int prepare_pstree_for_shell_job(void)
{
	pid_t current_sid = getsid(getpid());
	pid_t current_gid = getpgid(getpid());

	struct pstree_item *pi;

	pid_t old_sid;
	pid_t old_gid;

	if (!opts.shell_job)
		return 0;

	if (root_item->sid == root_item->pid.virt)
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

	old_sid = root_item->sid;
	old_gid = root_item->pgid;

	pr_info("Migrating process tree (GID %d->%d SID %d->%d)\n",
		old_gid, current_gid, old_sid, current_sid);

	for_each_pstree_item(pi) {
		if (pi->pgid == old_gid)
			pi->pgid = current_gid;
		if (pi->sid == old_sid)
			pi->sid = current_sid;
	}

	max_pid = max((int)current_sid, max_pid);
	max_pid = max((int)current_gid, max_pid);

	return 0;
}

static int read_pstree_image(void)
{
	int ret = 0, i, ps_fd, fd;
	struct pstree_item *pi, *parent = NULL;

	pr_info("Reading image tree\n");

	ps_fd = open_image(CR_FD_PSTREE, O_RSTR);
	if (ps_fd < 0)
		return ps_fd;

	while (1) {
		PstreeEntry *e;

		ret = pb_read_one_eof(ps_fd, &e, PB_PSTREE);
		if (ret <= 0)
			break;

		ret = -1;
		pi = alloc_pstree_item_with_rst();
		if (pi == NULL)
			break;

		pi->pid.virt = e->pid;
		max_pid = max((int)e->pid, max_pid);

		pi->pgid = e->pgid;
		max_pid = max((int)e->pgid, max_pid);

		pi->sid = e->sid;
		max_pid = max((int)e->sid, max_pid);

		if (e->ppid == 0) {
			if (root_item) {
				pr_err("Parent missed on non-root task "
				       "with pid %d, image corruption!\n", e->pid);
				goto err;
			}
			root_item = pi;
			pi->parent = NULL;
		} else {
			/*
			 * Fast path -- if the pstree image is not edited, the
			 * parent of any item should have already being restored
			 * and sit among the last item's ancestors.
			 */
			while (parent) {
				if (parent->pid.virt == e->ppid)
					break;
				parent = parent->parent;
			}

			if (parent == NULL) {
				for_each_pstree_item(parent) {
					if (parent->pid.virt == e->ppid)
						break;
				}

				if (parent == NULL) {
					pr_err("Can't find a parent for %d\n", pi->pid.virt);
					pstree_entry__free_unpacked(e, NULL);
					xfree(pi);
					goto err;
				}
			}

			pi->parent = parent;
			list_add(&pi->sibling, &parent->children);
		}

		parent = pi;

		pi->nr_threads = e->n_threads;
		pi->threads = xmalloc(e->n_threads * sizeof(struct pid));
		if (!pi->threads)
			break;

		for (i = 0; i < e->n_threads; i++) {
			pi->threads[i].real = -1;
			pi->threads[i].virt = e->threads[i];
		}

		task_entries->nr_threads += e->n_threads;
		task_entries->nr_tasks++;

		pstree_entry__free_unpacked(e, NULL);

		fd = open_image(CR_FD_IDS, O_RSTR, pi->pid.virt);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			goto err;
		}
		ret = pb_read_one(fd, &pi->ids, PB_IDS);
		close(fd);
		if (ret != 1)
			goto err;

		if (pi->ids->has_mnt_ns_id) {
			if (rst_add_ns_id(pi->ids->mnt_ns_id, pi->pid.virt, &mnt_ns_desc))
				goto err;
		}
	}
err:
	close(ps_fd);
	return ret;
}

static int prepare_pstree_ids(void)
{
	struct pstree_item *item, *child, *helper, *tmp;
	LIST_HEAD(helpers);

	pid_t current_pgid = getpgid(getpid());

	/*
	 * Some task can be reparented to init. A helper task should be added
	 * for restoring sid of such tasks. The helper tasks will be exited
	 * immediately after forking children and all children will be
	 * reparented to init.
	 */
	list_for_each_entry(item, &root_item->children, sibling) {

		/*
		 * If a child belongs to the root task's session or it's
		 * a session leader himself -- this is a simple case, we
		 * just proceed in a normal way.
		 */
		if (item->sid == root_item->sid || item->sid == item->pid.virt)
			continue;

		helper = alloc_pstree_item_with_rst();
		if (helper == NULL)
			return -1;
		helper->sid = item->sid;
		helper->pgid = item->sid;
		helper->pid.virt = item->sid;
		helper->state = TASK_HELPER;
		helper->parent = root_item;
		list_add_tail(&helper->sibling, &helpers);
		task_entries->nr_helpers++;

		pr_info("Add a helper %d for restoring SID %d\n",
				helper->pid.virt, helper->sid);

		child = list_entry(item->sibling.prev, struct pstree_item, sibling);
		item = child;

		/*
		 * Stack on helper task all children with target sid.
		 */
		list_for_each_entry_safe_continue(child, tmp, &root_item->children, sibling) {
			if (child->sid != helper->sid)
				continue;
			if (child->sid == child->pid.virt)
				continue;

			pr_info("Attach %d to the temporary task %d\n",
					child->pid.virt, helper->pid.virt);

			child->parent = helper;
			list_move(&child->sibling, &helper->children);
		}
	}

	/* Try to connect helpers to session leaders */
	for_each_pstree_item(item) {
		if (!item->parent) /* skip the root task */
			continue;

		if (item->state == TASK_HELPER)
			continue;

		if (item->sid != item->pid.virt) {
			struct pstree_item *parent;

			if (item->parent->sid == item->sid)
				continue;

			/* the task could fork a child before and after setsid() */
			parent = item->parent;
			while (parent && parent->pid.virt != item->sid) {
				if (parent->born_sid != -1 && parent->born_sid != item->sid) {
					pr_err("Can't determinate with which sid (%d or %d)"
						"the process %d was born\n",
						parent->born_sid, item->sid, parent->pid.virt);
					return -1;
				}
				parent->born_sid = item->sid;
				pr_info("%d was born with sid %d\n", parent->pid.virt, item->sid);
				parent = parent->parent;
			}

			if (parent == NULL) {
				pr_err("Can't find a session leader for %d\n", item->sid);
				return -1;
			}

			continue;
		}

		pr_info("Session leader %d\n", item->sid);

		/* Try to find helpers, who should be connected to the leader */
		list_for_each_entry(child, &helpers, sibling) {
			if (child->state != TASK_HELPER)
				continue;

			if (child->sid != item->sid)
				continue;

			child->pgid = item->pgid;
			child->pid.virt = ++max_pid;
			child->parent = item;
			list_move(&child->sibling, &item->children);

			pr_info("Attach %d to the task %d\n",
					child->pid.virt, item->pid.virt);

			break;
		}
	}

	/* All other helpers are session leaders for own sessions */
	list_splice(&helpers, &root_item->children);

	/* Add a process group leader if it is absent  */
	for_each_pstree_item(item) {
		struct pstree_item *gleader;

		if (!item->pgid || item->pid.virt == item->pgid)
			continue;

		for_each_pstree_item(gleader) {
			if (gleader->pid.virt == item->pgid)
				break;
		}

		if (gleader) {
			item->rst->pgrp_leader = gleader;
			continue;
		}

		/*
		 * If the PGID is eq to current one -- this
		 * means we're inheriting group from the current
		 * task so we need to escape creating a helper here.
		 */
		if (current_pgid == item->pgid)
			continue;

		helper = alloc_pstree_item_with_rst();
		if (helper == NULL)
			return -1;
		helper->sid = item->sid;
		helper->pgid = item->pgid;
		helper->pid.virt = item->pgid;
		helper->state = TASK_HELPER;
		helper->parent = item;
		list_add(&helper->sibling, &item->children);
		task_entries->nr_helpers++;
		item->rst->pgrp_leader = helper;

		pr_info("Add a helper %d for restoring PGID %d\n",
				helper->pid.virt, helper->pgid);
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

		if (!item->ids) {
			if (item == root_item) {
				cflags = opts.rst_namespaces_flags;
				goto set_mask;
			}

			continue;
		}

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

set_mask:
		item->rst->clone_flags = cflags;
		if (parent)
			/*
			 * Mount namespaces are setns()-ed at
			 * restore_task_mnt_ns() explicitly,
			 * no need in creating it with its own
			 * temporary namespace
			 */
			item->rst->clone_flags &= ~CLONE_NEWNS;

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

	ret = read_pstree_image();
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

	return ret;
}

bool restore_before_setsid(struct pstree_item *child)
{
	int csid = child->born_sid == -1 ? child->sid : child->born_sid;

	if (child->parent->born_sid == csid)
		return true;

	return false;
}

bool pid_in_pstree(pid_t pid)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		if (item->pid.real == pid)
			return true;
	}

	return false;
}
