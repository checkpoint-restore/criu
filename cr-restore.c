#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/shm.h>
#include <sys/mount.h>

#include <sched.h>

#include <sys/sendfile.h>

#include "compiler.h"
#include "types.h"

#include "image.h"
#include "util.h"
#include "log.h"
#include "syscall.h"
#include "restorer.h"
#include "sockets.h"
#include "lock.h"
#include "files.h"
#include "pipes.h"
#include "sk-inet.h"
#include "eventfd.h"
#include "eventpoll.h"
#include "proc_parse.h"
#include "restorer-blob.h"
#include "crtools.h"
#include "namespaces.h"
#include "shmem.h"
#include "mount.h"
#include "inotify.h"

static struct task_entries *task_entries;

static struct pstree_item *me;
static struct pstree_item *root_item = NULL;

static int restore_task_with_children(void *);
static int sigreturn_restore(pid_t pid, struct list_head *vmas, int nr_vmas);

static int shmem_remap(void *old_addr, void *new_addr, unsigned long size)
{
	void *ret;

	ret = mremap(old_addr, size, size,
			MREMAP_FIXED | MREMAP_MAYMOVE, new_addr);
	if (new_addr != ret) {
		pr_perror("mremap failed");
		return -1;
	}

	return 0;
}

static int max_pid = 0;
static int prepare_pstree(void)
{
	int ret = 0, i, ps_fd;
	struct pstree_item *pi, *parent = NULL;

	pr_info("Reading image tree\n");

	task_entries = mmap(NULL, TASK_ENTRIES_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (task_entries == MAP_FAILED) {
		pr_perror("Can't map shmem");
		return -1;
	}
	task_entries->nr = 0;
	task_entries->nr_tasks = 0;
	futex_set(&task_entries->start, CR_STATE_FORKING);

	ps_fd = open_image_ro(CR_FD_PSTREE);
	if (ps_fd < 0)
		return ps_fd;

	while (1) {
		struct pstree_entry e;

		ret = read_img_eof(ps_fd, &e);
		if (ret <= 0)
			break;

		ret = -1;
		pi = alloc_pstree_item_with_rst();
		if (pi == NULL)
			break;

		pi->pid.virt = e.pid;
		if (e.pid > max_pid)
			max_pid = e.pid;

		pi->pgid = e.pgid;
		if (e.pgid > max_pid)
			max_pid = e.pgid;

		pi->sid = e.sid;
		if (e.sid > max_pid)
			max_pid = e.sid;

		if (e.ppid == 0) {
			BUG_ON(root_item);
			root_item = pi;
			pi->parent = NULL;
			INIT_LIST_HEAD(&pi->list);
		} else {
			/*
			 * Fast path -- if the pstree image is not edited, the
			 * parent of any item should have already being restored
			 * and sit among the last item's ancestors.
			 */
			while (parent) {
				if (parent->pid.virt == e.ppid)
					break;
				parent = parent->parent;
			}

			if (parent == NULL)
				for_each_pstree_item(parent)
					if (parent->pid.virt == e.ppid)
						break;

			if (parent == NULL) {
				pr_err("Can't find a parent for %d", pi->pid.virt);
				xfree(pi);
				break;
			}

			pi->parent = parent;
			list_add(&pi->list, &parent->children);
		}

		parent = pi;

		pi->nr_threads = e.nr_threads;
		pi->threads = xmalloc(e.nr_threads * sizeof(struct pid));
		if (!pi->threads)
			break;

		ret = 0;
		for (i = 0; i < e.nr_threads; i++) {
			ret = read_img_buf(ps_fd, &pi->threads[i].virt, sizeof(u32));
			if (ret < 0)
				break;
		}
		if (ret < 0)
			break;

		task_entries->nr += e.nr_threads;
		task_entries->nr_tasks++;
	}

	if (!ret)
		futex_set(&task_entries->nr_in_progress, task_entries->nr_tasks);

	close(ps_fd);
	return ret;
}

static int prepare_pstree_ids(void)
{
	struct pstree_item *item, *child, *helper, *tmp;
	LIST_HEAD(helpers);

	/*
	 * Some task can be reparented to init. A helper task should be added
	 * for restoring sid of such tasks. The helper tasks will be exited
	 * immediately after forking children and all children will be
	 * reparented to init.
	 */
	list_for_each_entry(item, &root_item->children, list) {
		if (item->sid == root_item->sid || item->sid == item->pid.virt)
			continue;

		helper = alloc_pstree_item();
		if (helper == NULL)
			return -1;
		helper->sid = item->sid;
		helper->pgid = item->sid;
		helper->pid.virt = item->sid;
		helper->state = TASK_HELPER;
		helper->parent = root_item;
		list_add_tail(&helper->list, &helpers);

		pr_info("Add a helper %d for restoring SID %d\n",
				helper->pid.virt, helper->sid);

		child = list_entry(item->list.prev, struct pstree_item, list);
		item = child;

		list_for_each_entry_safe_continue(child, tmp, &root_item->children, list) {
			if (child->sid != helper->sid)
				continue;
			if (child->sid == child->pid.virt)
				continue;

			pr_info("Attach %d to the temporary task %d\n",
					child->pid.virt, helper->pid.virt);

			child->parent = helper;
			list_move(&child->list, &helper->children);
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
					pr_err("Can't determing with which sid (%d or %d)"
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
		list_for_each_entry(child, &helpers, list) {
			if (child->state != TASK_HELPER)
				continue;

			if (child->sid != item->sid)
				continue;

			child->pgid = item->pgid;
			child->pid.virt = ++max_pid;
			child->parent = item;
			list_move(&child->list, &item->children);

			pr_info("Attach %d to the task %d\n",
					child->pid.virt, item->pid.virt);

			break;
		}
	}

	/* All other helpers are session leaders for own sessions */
	list_splice(&helpers, &root_item->children);

	return 0;
}

static int prepare_shared(void)
{
	int ret = 0;
	struct pstree_item *pi;

	pr_info("Preparing info about shared resources\n");

	if (prepare_shmem_restore())
		return -1;

	if (prepare_shared_fdinfo())
		return -1;

	if (collect_reg_files())
		return -1;

	if (collect_pipes())
		return -1;

	if (collect_inet_sockets())
		return -1;

	if (collect_unix_sockets())
		return -1;

	if (collect_eventfd())
		return -1;

	if (collect_eventpoll())
		return -1;

	if (collect_mount_info())
		return -1;

	if (collect_inotify())
		return -1;

	for_each_pstree_item(pi) {
		ret = prepare_shmem_pid(pi->pid.virt);
		if (ret < 0)
			break;

		ret = prepare_fd_pid(pi->pid.virt, pi->rst);
		if (ret < 0)
			break;
	}

	mark_pipe_master();
	ret = resolve_unix_peers();

	if (!ret) {
		show_saved_shmems();
		show_saved_files();
	}

	return ret;
}

static int read_and_open_vmas(int pid, struct list_head *vmas, int *nr_vmas)
{
	int fd, ret = -1;

	fd = open_image_ro(CR_FD_VMAS, pid);
	if (fd < 0)
		return fd;

	*nr_vmas = 0;
	while (1) {
		struct vma_area *vma;

		ret = -1;
		vma = alloc_vma_area();
		if (!vma)
			break;

		(*nr_vmas)++;
		list_add_tail(&vma->list, vmas);
		ret = read_img_eof(fd, &vma->vma);
		if (ret <= 0)
			break;

		if (!(vma_entry_is(&vma->vma, VMA_AREA_REGULAR)))
			continue;

		pr_info("Opening 0x%016lx-0x%016lx 0x%016lx vma\n",
				vma->vma.start, vma->vma.end, vma->vma.pgoff);

		if (vma_entry_is(&vma->vma, VMA_AREA_SYSVIPC))
			ret = vma->vma.shmid;
		else if (vma_entry_is(&vma->vma, VMA_ANON_SHARED))
			ret = get_shmem_fd(pid, &vma->vma);
		else if (vma_entry_is(&vma->vma, VMA_FILE_PRIVATE) ||
				vma_entry_is(&vma->vma, VMA_FILE_SHARED))
			ret = get_filemap_fd(pid, &vma->vma);
		else
			continue;

		if (ret < 0) {
			pr_err("Can't fixup fd\n");
			break;
		}

		vma->vma.fd = ret;
	}

	close(fd);
	return ret;
}

static int prepare_and_sigreturn(int pid)
{
	int err, nr_vmas;
	LIST_HEAD(vma_list);

	err = read_and_open_vmas(pid, &vma_list, &nr_vmas);
	if (err)
		return err;

	return sigreturn_restore(pid, &vma_list, nr_vmas);
}

static rt_sigaction_t sigchld_act;
static int prepare_sigactions(int pid)
{
	rt_sigaction_t act, oact;
	int fd_sigact;
	struct sa_entry e;
	int sig;
	int ret = -1;

	fd_sigact = open_image_ro(CR_FD_SIGACT, pid);
	if (fd_sigact < 0)
		return -1;

	for (sig = 1; sig < SIGMAX; sig++) {
		if (sig == SIGKILL || sig == SIGSTOP)
			continue;

		ret = read_img(fd_sigact, &e);
		if (ret < 0)
			break;

		ASSIGN_TYPED(act.rt_sa_handler, e.sigaction);
		ASSIGN_TYPED(act.rt_sa_flags, e.flags);
		ASSIGN_TYPED(act.rt_sa_restorer, e.restorer);
		ASSIGN_TYPED(act.rt_sa_mask.sig[0], e.mask);

		if (sig == SIGCHLD) {
			sigchld_act = act;
			continue;
		}
		/*
		 * A pure syscall is used, because glibc
		 * sigaction overwrites se_restorer.
		 */
		ret = sys_sigaction(sig, &act, &oact, sizeof(rt_sigset_t));
		if (ret == -1) {
			pr_err("%d: Can't restore sigaction: %m\n", pid);
			goto err;
		}
	}

err:
	close_safe(&fd_sigact);
	return ret;
}

static int pstree_wait_helpers()
{
	struct pstree_item *pi;

	list_for_each_entry(pi, &me->children, list) {
		int status, ret;

		if (pi->state != TASK_HELPER)
			continue;

		/* Check, that a helper completed. */
		ret = waitpid(pi->pid.virt, &status, 0);
		if (ret == -1) {
			if (errno == ECHILD)
				continue; /* It has been waited in sigchld_handler */
			pr_err("waitpid(%d) failed\n", pi->pid.virt);
			return -1;
		}
		if (!WIFEXITED(status) || WEXITSTATUS(status)) {
			pr_err("%d exited with non-zero code (%d,%d)", pi->pid.virt,
				WEXITSTATUS(status), WTERMSIG(status));
			return -1;
		}

	}

	return 0;
}

static int restore_one_alive_task(int pid)
{
	pr_info("Restoring resources\n");

	if (pstree_wait_helpers())
		return -1;

	if (prepare_fds(me))
		return -1;

	if (prepare_fs(pid))
		return -1;

	if (prepare_sigactions(pid))
		return -1;

	return prepare_and_sigreturn(pid);
}

static void zombie_prepare_signals(void)
{
	sigset_t blockmask;
	int sig;
	struct sigaction act;

	sigfillset(&blockmask);
	sigprocmask(SIG_UNBLOCK, &blockmask, NULL);

	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_DFL;

	for (sig = 1; sig < SIGMAX; sig++)
		sigaction(sig, &act, NULL);
}

#define SIG_FATAL_MASK	(	\
		(1 << SIGHUP)	|\
		(1 << SIGINT)	|\
		(1 << SIGQUIT)	|\
		(1 << SIGILL)	|\
		(1 << SIGTRAP)	|\
		(1 << SIGABRT)	|\
		(1 << SIGIOT)	|\
		(1 << SIGBUS)	|\
		(1 << SIGFPE)	|\
		(1 << SIGKILL)	|\
		(1 << SIGUSR1)	|\
		(1 << SIGSEGV)	|\
		(1 << SIGUSR2)	|\
		(1 << SIGPIPE)	|\
		(1 << SIGALRM)	|\
		(1 << SIGTERM)	|\
		(1 << SIGXCPU)	|\
		(1 << SIGXFSZ)	|\
		(1 << SIGVTALRM)|\
		(1 << SIGPROF)	|\
		(1 << SIGPOLL)	|\
		(1 << SIGIO)	|\
		(1 << SIGSYS)	|\
		(1 << SIGUNUSED)|\
		(1 << SIGSTKFLT)|\
		(1 << SIGPWR)	 \
	)

static inline int sig_fatal(int sig)
{
	return (sig > 0) && (sig < SIGMAX) && (SIG_FATAL_MASK & (1 << sig));
}

static int restore_one_fake(int pid)
{
	/* We should wait here, otherwise last_pid will be changed. */
	futex_wait_while(&task_entries->start, CR_STATE_FORKING);
	return 0;
}

static int restore_one_zombie(int pid, int exit_code)
{
	pr_info("Restoring zombie with %d code\n", exit_code);

	if (task_entries != NULL) {
		futex_dec_and_wake(&task_entries->nr_in_progress);
		futex_wait_while(&task_entries->start, CR_STATE_RESTORE);

		zombie_prepare_signals();

		futex_dec_and_wake(&task_entries->nr_in_progress);
		futex_wait_while(&task_entries->start, CR_STATE_RESTORE_SIGCHLD);
	}

	if (exit_code & 0x7f) {
		int signr;

		signr = exit_code & 0x7F;
		if (!sig_fatal(signr)) {
			pr_warn("Exit with non fatal signal ignored\n");
			signr = SIGABRT;
		}

		if (kill(pid, signr) < 0)
			pr_perror("Can't kill myself, will just exit");

		exit_code = 0;
	}

	exit((exit_code >> 8) & 0x7f);

	/* never reached */
	BUG_ON(1);
	return -1;
}

static int check_core_header(int pid, struct task_core_entry *tc)
{
	int fd = -1, ret = -1;
	struct image_header hdr;

	fd = open_image_ro(CR_FD_CORE, pid);
	if (fd < 0)
		return -1;

	if (read_img(fd, &hdr) < 0)
		goto out;

	if (hdr.version != HEADER_VERSION) {
		pr_err("Core version mismatch %d\n", (int)hdr.version);
		goto out;
	}

	if (hdr.arch != HEADER_ARCH_X86_64) {
		pr_err("Core arch mismatch %d\n", (int)hdr.arch);
		goto out;
	}

	ret = read_img(fd, tc);
out:
	close_safe(&fd);
	return ret < 0 ? ret : 0;
}

static int restore_one_task(int pid)
{
	struct task_core_entry tc;

	if (me->state == TASK_HELPER)
		return restore_one_fake(pid);

	if (check_core_header(pid, &tc))
		return -1;

	switch ((int)tc.task_state) {
	case TASK_ALIVE:
		return restore_one_alive_task(pid);
	case TASK_DEAD:
		return restore_one_zombie(pid, tc.exit_code);
	default:
		pr_err("Unknown state in code %d\n", (int)tc.task_state);
		return -1;
	}
}

/*
 * This stack size is important for the restorer
 * itself only. At the final phase, we will switch
 * to the original stack the program had at checkpoint
 * time.
 */
#define STACK_SIZE	(8 * 4096)
struct cr_clone_arg {
	struct pstree_item *item;
	unsigned long clone_flags;
	int fd;
};

static inline int fork_with_pid(struct pstree_item *item, unsigned long ns_clone_flags)
{
	int ret = -1;
	char buf[32];
	struct cr_clone_arg ca;
	void *stack;
	pid_t pid = item->pid.virt;

	pr_info("Forking task with %d pid (flags 0x%lx)\n", pid, ns_clone_flags);

	stack = mmap(NULL, STACK_SIZE, PROT_WRITE | PROT_READ,
			MAP_PRIVATE | MAP_GROWSDOWN | MAP_ANONYMOUS, -1, 0);
	if (stack == MAP_FAILED) {
		pr_perror("Failed to map stack for the child");
		goto err;
	}

	snprintf(buf, sizeof(buf), "%d", pid - 1);
	ca.item = item;
	ca.clone_flags = ns_clone_flags;
	ca.fd = open(LAST_PID_PATH, O_RDWR);
	if (ca.fd < 0) {
		pr_perror("%d: Can't open %s", pid, LAST_PID_PATH);
		goto err;
	}

	if (flock(ca.fd, LOCK_EX)) {
		pr_perror("%d: Can't lock %s", pid, LAST_PID_PATH);
		goto err_close;
	}

	if (!(ca.clone_flags & CLONE_NEWPID)) {
		if (write_img_buf(ca.fd, buf, strlen(buf)))
			goto err_unlock;
	} else
		BUG_ON(pid != 1);

	ret = clone(restore_task_with_children, stack + STACK_SIZE,
			ca.clone_flags | SIGCHLD, &ca);

	if (ret < 0)
		pr_perror("Can't fork for %d", pid);

err_unlock:
	if (flock(ca.fd, LOCK_UN))
		pr_perror("%d: Can't unlock %s", pid, LAST_PID_PATH);

err_close:
	close_safe(&ca.fd);
err:
	if (stack != MAP_FAILED)
		munmap(stack, STACK_SIZE);
	return ret;
}

static void sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	struct pstree_item *pi;
	pid_t pid = siginfo->si_pid;
	int status;
	int exit;

	exit = siginfo->si_code & CLD_EXITED;
	status = siginfo->si_status;
	if (!me || status)
		goto err;

	/* Skip a helper if it was completed successfully */
	while (pid) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid <= 0)
			return;

		exit = WIFEXITED(status);
		status = exit ? WEXITSTATUS(status) : WTERMSIG(status);
		if (status)
			break;

		list_for_each_entry(pi, &me->children, list) {
			if (pi->state != TASK_HELPER)
				continue;
			if (pi->pid.virt == siginfo->si_pid)
				break;
		}

		if (&pi->list == &me->children)
			break; /* The process is not a helper */
	}

err:
	if (exit)
		pr_err("%d exited, status=%d\n", pid, status);
	else
		pr_err("%d killed by signal %d\n", pid, status);

	futex_abort_and_wake(&task_entries->nr_in_progress);
}

/* 
 * FIXME Din't fail on xid restore failure. MySQL uses runaway
 * pgid and sid and there's nothing we can do about it yet :(
 */

static void xid_fail(void)
{
	exit(1);
}

static void restore_sid(void)
{
	pid_t sid;

	/*
	 * SID can only be reset to pid or inherited from parent.
	 * Thus we restore it right here to let our kids inherit
	 * one in case they need it.
	 *
	 * PGIDs are restored late when all tasks are forked and
	 * we can call setpgid() on custom values.
	 */

	if (me->pid.virt == me->sid) {
		pr_info("Restoring %d to %d sid\n", me->pid.virt, me->sid);
		sid = setsid();
		if (sid != me->sid) {
			pr_perror("Can't restore sid (%d)", sid);
			xid_fail();
		}
	} else {
		sid = getsid(getppid());
		if (sid != me->sid) {
			/* Skip the root task if it's not init */
			if (me == root_item && root_item->pid.virt != 1)
				return;
			pr_err("Requested sid %d doesn't match inherited %d\n",
					me->sid, sid);
			xid_fail();
		}
	}
}

static void restore_pgid(void)
{
	pid_t pgid;

	pr_info("Restoring %d to %d pgid\n", me->pid.virt, me->pgid);

	pgid = getpgrp();
	if (me->pgid == pgid)
		return;

	pr_info("\twill call setpgid, mine pgid is %d\n", pgid);
	if (setpgid(0, me->pgid) != 0) {
		pr_perror("Can't restore pgid (%d/%d->%d)", me->pid.virt, pgid, me->pgid);
		xid_fail();
	}
}

static char proc_mountpoint[PATH_MAX] = "/proc";

static bool restore_before_setsid(struct pstree_item *child)
{
	int csid = child->born_sid == -1 ? child->sid : child->born_sid;

	if (child->parent->born_sid == csid)
		return true;

	return false;
}

static int restore_task_with_children(void *_arg)
{
	struct cr_clone_arg *ca = _arg;
	struct pstree_item *child;
	pid_t pid;
	int ret;
	sigset_t blockmask;

	close_safe(&ca->fd);

	me = ca->item;

	pid = getpid();
	if (me->pid.virt != pid) {
		pr_err("Pid %d do not match expected %d\n", pid, me->pid.virt);
		exit(-1);
	}

	if (pid == 1) { /* New pid namespace */
		ret = mount("proc", proc_mountpoint, "proc", MS_MGC_VAL, NULL);
		if (ret == -1) {
			pr_err("mount failed");
			exit(1);
		}
		set_proc_mountpoint(proc_mountpoint);
	}

	ret = log_init_by_pid();
	if (ret < 0)
		exit(1);

	if (ca->clone_flags) {
		ret = prepare_namespace(me->pid.virt, ca->clone_flags);
		if (ret)
			exit(-1);
	}

	/*
	 * The block mask will be restored in sigresturn.
	 *
	 * TODO: This code should be removed, when a freezer will be added.
	 */
	sigfillset(&blockmask);
	sigdelset(&blockmask, SIGCHLD);
	ret = sigprocmask(SIG_BLOCK, &blockmask, NULL);
	if (ret) {
		pr_perror("%d: Can't block signals", me->pid.virt);
		exit(1);
	}

	pr_info("Restoring children:\n");
	list_for_each_entry(child, &me->children, list) {
		if (!restore_before_setsid(child))
			continue;

		BUG_ON(child->born_sid != -1 && getsid(getpid()) != child->born_sid);

		ret = fork_with_pid(child, 0);
		if (ret < 0)
			exit(1);
	}

	restore_sid();

	pr_info("Restoring children:\n");
	list_for_each_entry(child, &me->children, list) {
		if (restore_before_setsid(child))
			continue;
		ret = fork_with_pid(child, 0);
		if (ret < 0)
			exit(1);
	}

	if (me->state != TASK_HELPER) {
		futex_dec_and_wake(&task_entries->nr_in_progress);
		futex_wait_while(&task_entries->start, CR_STATE_FORKING);
	}

	restore_pgid();

	return restore_one_task(me->pid.virt);
}

static int restore_root_task(struct pstree_item *init, struct cr_options *opts)
{
	int ret;
	struct sigaction act, old_act;

	ret = sigaction(SIGCHLD, NULL, &act);
	if (ret < 0) {
		perror("sigaction() failed\n");
		return -1;
	}

	act.sa_flags |= SA_NOCLDSTOP | SA_SIGINFO | SA_RESTART;
	act.sa_sigaction = sigchld_handler;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGCHLD);

	ret = sigaction(SIGCHLD, &act, &old_act);
	if (ret < 0) {
		perror("sigaction() failed\n");
		return -1;
	}

	/*
	 * FIXME -- currently we assume that all the tasks live
	 * in the same set of namespaces. This is done to debug
	 * the ns contents dumping/restoring. Need to revisit
	 * this later.
	 */

	if (init->pid.virt == 1) {
		if (!(opts->namespaces_flags & CLONE_NEWPID)) {
			pr_err("This process tree can be restored in a new pid namespace.\n");
			pr_err("crtools should be re-executed with --namespace pid\n");
			return -1;
		}

		snprintf(proc_mountpoint, sizeof(proc_mountpoint), "/tmp/crtools-proc.XXXXXX");
		if (mkdtemp(proc_mountpoint) == NULL) {
			pr_err("mkdtemp failed %m");
			return -1;
		}

	} else	if (opts->namespaces_flags & CLONE_NEWPID) {
		pr_err("Can't restore pid namespace without the process init\n");
		return -1;
	}


	ret = fork_with_pid(init, opts->namespaces_flags);
	if (ret < 0)
		return -1;

	pr_info("Wait until all tasks are forked\n");
	futex_wait_while_gt(&task_entries->nr_in_progress, 0);
	ret = (int)futex_get(&task_entries->nr_in_progress);
	if (ret < 0)
		goto out;

	futex_set_and_wake(&task_entries->nr_in_progress, task_entries->nr);
	futex_set_and_wake(&task_entries->start, CR_STATE_RESTORE);

	pr_info("Wait until all tasks are restored\n");
	futex_wait_while_gt(&task_entries->nr_in_progress, 0);
	ret = (int)futex_get(&task_entries->nr_in_progress);

out:
	if (init->pid.virt == 1) {
		int err;
		err = umount(proc_mountpoint);
		if (err == -1)
			pr_err("Can't umount %s\n", proc_mountpoint);
		err = rmdir(proc_mountpoint);
		if (err == -1)
			pr_err("Can't delete %s\n", proc_mountpoint);
	}

	if (ret < 0) {
		struct pstree_item *pi;
		pr_err("Someone can't be restored\n");

		for_each_pstree_item(pi)
			kill(pi->pid.virt, SIGKILL);

		return 1;
	}

	futex_set_and_wake(&task_entries->nr_in_progress, task_entries->nr);
	futex_set_and_wake(&task_entries->start, CR_STATE_RESTORE_SIGCHLD);
	futex_wait_until(&task_entries->nr_in_progress, 0);

	ret = sigaction(SIGCHLD, &old_act, NULL);
	if (ret < 0) {
		perror("sigaction() failed\n");
		return -1;
	}

	/*
	 * Maybe rework ghosts to be auto-unlinkable?
	 */

	clear_ghost_files();
	tcp_unlock_connections();

	pr_info("Go on!!!\n");
	futex_set_and_wake(&task_entries->start, CR_STATE_COMPLETE);

	if (!opts->restore_detach)
		wait(NULL);
	return 0;
}

static int restore_all_tasks(pid_t pid, struct cr_options *opts)
{
	if (prepare_pstree() < 0)
		return -1;

	if (prepare_shared() < 0)
		return -1;

	if (prepare_pstree_ids() < 0)
		return -1;

	return restore_root_task(root_item, opts);
}

#define TASK_SIZE_MAX   ((1UL << 47) - PAGE_SIZE)
static long restorer_get_vma_hint(pid_t pid, struct list_head *tgt_vma_list,
		struct list_head *self_vma_list, long vma_len)
{
	struct vma_area *t_vma, *s_vma;
	long prev_vma_end = 0;
	struct vma_area end_vma;

	end_vma.vma.start = end_vma.vma.end = TASK_SIZE_MAX;
	prev_vma_end = PAGE_SIZE;

	/*
	 * Here we need some heuristics -- the VMA which restorer will
	 * belong to should not be unmapped, so we need to gueess out
	 * where to put it in.
	 */

	s_vma = list_first_entry(self_vma_list, struct vma_area, list);
	t_vma = list_first_entry(tgt_vma_list, struct vma_area, list);

	while (1) {
		if (prev_vma_end + vma_len > s_vma->vma.start) {
			if (s_vma->list.next == self_vma_list) {
				s_vma = &end_vma;
				continue;
			}
			if (s_vma == &end_vma)
				break;
			if (prev_vma_end < s_vma->vma.end)
				prev_vma_end = s_vma->vma.end;
			s_vma = list_entry(s_vma->list.next, struct vma_area, list);
			continue;
		}

		if (prev_vma_end + vma_len > t_vma->vma.start) {
			if (t_vma->list.next == tgt_vma_list) {
				t_vma = &end_vma;
				continue;
			}
			if (t_vma == &end_vma)
				break;
			if (prev_vma_end < t_vma->vma.end)
				prev_vma_end = t_vma->vma.end;
			t_vma = list_entry(t_vma->list.next, struct vma_area, list);
			continue;
		}

		return prev_vma_end;
	}

	return -1;
}

#define USEC_PER_SEC	1000000L

static inline int timeval_valid(struct timeval *tv)
{
	return (tv->tv_sec >= 0) && ((unsigned long)tv->tv_usec < USEC_PER_SEC);
}

static inline int itimer_restore_and_fix(char *n, struct itimer_entry *ie,
		struct itimerval *val)
{
	if (ie->isec == 0 && ie->iusec == 0) {
		memzero_p(val);
		return 0;
	}

	val->it_interval.tv_sec = ie->isec;
	val->it_interval.tv_usec = ie->iusec;

	if (!timeval_valid(&val->it_interval)) {
		pr_err("Invalid timer interval\n");
		return -1;
	}

	if (ie->vsec == 0 && ie->vusec == 0) {
		/*
		 * Remaining time was too short. Set it to
		 * interval to make the timer armed and work.
		 */
		val->it_value.tv_sec = ie->isec;
		val->it_value.tv_usec = ie->iusec;
	} else {
		val->it_value.tv_sec = ie->vsec;
		val->it_value.tv_usec = ie->vusec;
	}

	if (!timeval_valid(&val->it_value)) {
		pr_err("Invalid timer value\n");
		return -1;
	}

	pr_info("Restored %s timer to %ld.%ld -> %ld.%ld\n", n,
			val->it_value.tv_sec, val->it_value.tv_usec,
			val->it_interval.tv_sec, val->it_interval.tv_usec);

	return 0;
}

static int prepare_itimers(int pid, struct task_restore_core_args *args)
{
	int fd, ret = -1;
	struct itimer_entry ie[3];

	fd = open_image_ro(CR_FD_ITIMERS, pid);
	if (fd < 0)
		return fd;

	if (read_img_buf(fd, ie, sizeof(ie)) > 0) {
		ret = itimer_restore_and_fix("real",
				&ie[0], &args->itimers[0]);
		if (!ret)
			ret = itimer_restore_and_fix("virt",
					&ie[1], &args->itimers[1]);
		if (!ret)
			ret = itimer_restore_and_fix("prof",
					&ie[2], &args->itimers[2]);
	}

	close_safe(&fd);
	return ret;
}

static int prepare_creds(int pid, struct task_restore_core_args *args)
{
	int fd, ret;

	fd = open_image_ro(CR_FD_CREDS, pid);
	if (fd < 0)
		return fd;

	ret = read_img(fd, &args->creds);

	close_safe(&fd);

	/* XXX -- validate creds here? */

	return ret > 0 ? 0 : -1;
}

static struct vma_entry *vma_list_remap(void *addr, unsigned long len, struct list_head *vmas)
{
	struct vma_entry *vma, *ret;
	struct vma_area *vma_area;

	ret = vma = mmap(addr, len, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
	if (vma != addr) {
		pr_perror("Can't remap vma area");
		return NULL;
	}

	list_for_each_entry(vma_area, vmas, list) {
		*vma = vma_area->vma;
		vma++;
	}

	vma->start = 0;
	free_mappings(vmas);

	return ret;
}

static int prepare_mm(pid_t pid, struct task_restore_core_args *args)
{
	int fd, exe_fd;

	fd = open_image_ro(CR_FD_MM, pid);
	if (fd < 0)
		return -1;

	if (read_img(fd, &args->mm) < 0)
		return -1;

	exe_fd = open_reg_by_id(args->mm.exe_file_id);
	if (exe_fd < 0)
		return -1;

	args->fd_exe_link = exe_fd;

	close(fd);
	return 0;
}

static int sigreturn_restore(pid_t pid, struct list_head *tgt_vmas, int nr_vmas)
{
	long restore_code_len, restore_task_vma_len;
	long restore_thread_vma_len, self_vmas_len, vmas_len;

	void *mem = MAP_FAILED;
	void *restore_thread_exec_start;
	void *restore_task_exec_start;
	void *restore_code_start;

	long new_sp, exec_mem_hint;
	long ret;

	struct task_restore_core_args *task_args;
	struct thread_restore_args *thread_args;

	LIST_HEAD(self_vma_list);
	int fd_core = -1;
	int fd_pages = -1;
	int i;

	pr_info("Restore via sigreturn\n");

	restore_code_len	= 0;
	restore_task_vma_len	= 0;
	restore_thread_vma_len	= 0;

	ret = parse_smaps(pid, &self_vma_list, false);
	close_proc();
	if (ret < 0)
		goto err;

	self_vmas_len = round_up((ret + 1) * sizeof(struct vma_entry), PAGE_SIZE);
	vmas_len = round_up((nr_vmas + 1) * sizeof(struct vma_entry), PAGE_SIZE);

	/* pr_info_vma_list(&self_vma_list); */

	BUILD_BUG_ON(sizeof(struct task_restore_core_args) & 1);
	BUILD_BUG_ON(sizeof(struct thread_restore_args) & 1);
	BUILD_BUG_ON(SHMEMS_SIZE % PAGE_SIZE);
	BUILD_BUG_ON(TASK_ENTRIES_SIZE % PAGE_SIZE);

	fd_core = open_image_ro(CR_FD_CORE, pid);
	if (fd_core < 0) {
		pr_perror("Can't open core-out-%d", pid);
		goto err;
	}

	fd_pages = open_image_ro(CR_FD_PAGES, pid);
	if (fd_pages < 0) {
		pr_perror("Can't open pages-%d", pid);
		goto err;
	}

	restore_code_len	= sizeof(restorer_blob);
	restore_code_len	= round_up(restore_code_len, 16);

	restore_task_vma_len	= round_up(restore_code_len + sizeof(*task_args), PAGE_SIZE);

	/*
	 * Thread statistics
	 */

	/*
	 * Compute how many memory we will need
	 * to restore all threads, every thread
	 * requires own stack and heap, it's ~40K
	 * per thread.
	 */

	restore_thread_vma_len = sizeof(*thread_args) * me->nr_threads;
	restore_thread_vma_len = round_up(restore_thread_vma_len, 16);

	pr_info("%d threads require %ldK of memory\n",
			me->nr_threads,
			KBYTES(restore_thread_vma_len));

	restore_thread_vma_len = round_up(restore_thread_vma_len, PAGE_SIZE);

	exec_mem_hint = restorer_get_vma_hint(pid, tgt_vmas, &self_vma_list,
					      restore_task_vma_len +
					      restore_thread_vma_len +
					      self_vmas_len +
					      SHMEMS_SIZE + TASK_ENTRIES_SIZE);
	if (exec_mem_hint == -1) {
		pr_err("No suitable area for task_restore bootstrap (%ldK)\n",
		       restore_task_vma_len + restore_thread_vma_len);
		goto err;
	}

	pr_info("Found bootstrap VMA hint at: 0x%lx (needs ~%ldK)\n", exec_mem_hint,
			KBYTES(restore_task_vma_len + restore_thread_vma_len));

	/* VMA we need to run task_restore code */
	mem = mmap((void *)exec_mem_hint,
			restore_task_vma_len + restore_thread_vma_len,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
	if (mem != (void *)exec_mem_hint) {
		pr_err("Can't mmap section for restore code\n");
		goto err;
	}

	/*
	 * Prepare a memory map for restorer. Note a thread space
	 * might be completely unused so it's here just for convenience.
	 */
	restore_code_start		= mem;
	restore_thread_exec_start	= restore_code_start + restorer_blob_offset____export_restore_thread;
	restore_task_exec_start		= restore_code_start + restorer_blob_offset____export_restore_task;
	task_args			= restore_code_start + restore_code_len;
	thread_args			= (void *)((long)task_args + sizeof(*task_args));

	memzero_p(task_args);
	memzero(thread_args, sizeof(*thread_args) * me->nr_threads);

	/*
	 * Code at a new place.
	 */
	memcpy(restore_code_start, &restorer_blob, sizeof(restorer_blob));

	/*
	 * Adjust stack.
	 */
	new_sp = RESTORE_ALIGN_STACK((long)task_args->mem_zone.stack, sizeof(task_args->mem_zone.stack));

	/*
	 * Get a reference to shared memory area which is
	 * used to signal if shmem restoration complete
	 * from low-level restore code.
	 *
	 * This shmem area is mapped right after the whole area of
	 * sigreturn rt code. Note we didn't allocated it before
	 * but this area is taken into account for 'hint' memory
	 * address.
	 */

	mem += restore_task_vma_len + restore_thread_vma_len;
	ret = shmem_remap(rst_shmems, mem, SHMEMS_SIZE);
	if (ret < 0)
		goto err;
	task_args->shmems = mem;

	mem += SHMEMS_SIZE;
	ret = shmem_remap(task_entries, mem, TASK_ENTRIES_SIZE);
	if (ret < 0)
		goto err;
	task_args->task_entries = mem;

	mem += TASK_ENTRIES_SIZE;
	task_args->self_vmas = vma_list_remap(mem, self_vmas_len, &self_vma_list);
	if (!task_args->self_vmas)
		goto err;

	mem += self_vmas_len;
	task_args->tgt_vmas = vma_list_remap(mem, vmas_len, tgt_vmas);
	if (!task_args->tgt_vmas)
		goto err;

	/*
	 * Arguments for task restoration.
	 */
	task_args->pid		= pid;
	task_args->fd_core	= fd_core;
	task_args->logfd	= log_get_fd();
	task_args->sigchld_act	= sigchld_act;
	task_args->fd_pages	= fd_pages;

	ret = prepare_itimers(pid, task_args);
	if (ret < 0)
		goto err;

	ret = prepare_creds(pid, task_args);
	if (ret < 0)
		goto err;

	ret = prepare_mm(pid, task_args);
	if (ret < 0)
		goto err;

	mutex_init(&task_args->rst_lock);

	/*
	 * Now prepare run-time data for threads restore.
	 */
	task_args->nr_threads		= me->nr_threads;
	task_args->clone_restore_fn	= (void *)restore_thread_exec_start;
	task_args->thread_args		= thread_args;

	/*
	 * Fill up per-thread data.
	 */
	for (i = 0; i < me->nr_threads; i++) {
		thread_args[i].pid = me->threads[i].virt;

		/* skip self */
		if (thread_args[i].pid == pid)
			continue;

		/* Core files are to be opened */
		thread_args[i].fd_core = open_image_ro(CR_FD_CORE, thread_args[i].pid);
		if (thread_args[i].fd_core < 0)
			goto err;

		thread_args[i].rst_lock = &task_args->rst_lock;

		pr_info("Thread %4d stack %8p heap %8p rt_sigframe %8p\n",
				i, thread_args[i].mem_zone.stack,
				thread_args[i].mem_zone.heap,
				thread_args[i].mem_zone.rt_sigframe);

	}

	close_image_dir();

	pr_info("task_args: %p\n"
		"task_args->pid: %d\n"
		"task_args->fd_core: %d\n"
		"task_args->nr_threads: %d\n"
		"task_args->clone_restore_fn: %p\n"
		"task_args->thread_args: %p\n",
		task_args, task_args->pid,
		task_args->fd_core,
		task_args->nr_threads,
		task_args->clone_restore_fn,
		task_args->thread_args);

	/*
	 * An indirect call to task_restore, note it never resturns
	 * and restoreing core is extremely destructive.
	 */
	asm volatile(
		"movq %0, %%rbx						\n"
		"movq %1, %%rax						\n"
		"movq %2, %%rdi						\n"
		"movq %%rbx, %%rsp					\n"
		"callq *%%rax						\n"
		:
		: "g"(new_sp),
		  "g"(restore_task_exec_start),
		  "g"(task_args)
		: "rsp", "rdi", "rsi", "rbx", "rax", "memory");

err:
	free_mappings(&self_vma_list);
	close_safe(&fd_core);

	/* Just to be sure */
	exit(1);
	return -1;
}

int cr_restore_tasks(pid_t pid, struct cr_options *opts)
{
	if (opts->leader_only)
		return restore_one_task(pid);
	return restore_all_tasks(pid, opts);
}
