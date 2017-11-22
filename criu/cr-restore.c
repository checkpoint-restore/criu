#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>

#include <fcntl.h>
#include <grp.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/shm.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sched.h>

#include <sys/sendfile.h>

#include "types.h"
#include <compel/ptrace.h>
#include "common/compiler.h"

#include "clone-noasan.h"
#include "cr_options.h"
#include "servicefd.h"
#include "image.h"
#include "util.h"
#include "util-pie.h"
#include "criu-log.h"
#include "restorer.h"
#include "sockets.h"
#include "sk-packet.h"
#include "common/lock.h"
#include "files.h"
#include "files-reg.h"
#include "pipes.h"
#include "fifo.h"
#include "sk-inet.h"
#include "eventfd.h"
#include "eventpoll.h"
#include "signalfd.h"
#include "proc_parse.h"
#include "pie/restorer-blob.h"
#include "crtools.h"
#include "uffd.h"
#include "namespaces.h"
#include "mem.h"
#include "mount.h"
#include "fsnotify.h"
#include "pstree.h"
#include "net.h"
#include "tty.h"
#include "cpu.h"
#include "file-lock.h"
#include "vdso.h"
#include "stats.h"
#include "tun.h"
#include "vma.h"
#include "kerndat.h"
#include "rst-malloc.h"
#include "plugin.h"
#include "cgroup.h"
#include "timerfd.h"
#include "file-lock.h"
#include "action-scripts.h"
#include "shmem.h"
#include <compel/compel.h>
#include "aio.h"
#include "lsm.h"
#include "seccomp.h"
#include "fault-injection.h"
#include "sk-queue.h"
#include "sigframe.h"
#include "fdstore.h"

#include "parasite-syscall.h"
#include "files-reg.h"
#include <compel/plugins/std/syscall-codes.h>
#include "compel/include/asm/syscall.h"

#include "protobuf.h"
#include "images/sa.pb-c.h"
#include "images/timer.pb-c.h"
#include "images/vma.pb-c.h"
#include "images/rlimit.pb-c.h"
#include "images/pagemap.pb-c.h"
#include "images/siginfo.pb-c.h"

#include "restore.h"

#include "cr-errno.h"

#include "pie/pie-relocs.h"

#ifndef arch_export_restore_thread
#define arch_export_restore_thread	__export_restore_thread
#endif

#ifndef arch_export_restore_task
#define arch_export_restore_task	__export_restore_task
#endif

#ifndef arch_export_unmap
#define arch_export_unmap		__export_unmap
#define arch_export_unmap_compat	__export_unmap_compat
#endif

struct pstree_item *current;

static int restore_task_with_children(void *);
static int sigreturn_restore(pid_t pid, struct task_restore_args *ta, unsigned long alen, CoreEntry *core);
static int prepare_restorer_blob(void);
static int prepare_rlimits(int pid, struct task_restore_args *, CoreEntry *core);
static int prepare_posix_timers(int pid, struct task_restore_args *ta, CoreEntry *core);
static int prepare_signals(int pid, struct task_restore_args *, CoreEntry *core);

/*
 * Architectures can overwrite this function to restore registers that are not
 * present in the sigreturn signal frame.
 */
int __attribute__((weak)) arch_set_thread_regs_nosigrt(struct pid *pid)
{
	return 0;
}

static inline int stage_participants(int next_stage)
{
	switch (next_stage) {
	case CR_STATE_FAIL:
		return 0;
	case CR_STATE_ROOT_TASK:
	case CR_STATE_PREPARE_NAMESPACES:
		return 1;
	case CR_STATE_FORKING:
		return task_entries->nr_tasks + task_entries->nr_helpers;
	case CR_STATE_RESTORE:
		return task_entries->nr_threads + task_entries->nr_helpers;
	case CR_STATE_RESTORE_SIGCHLD:
		return task_entries->nr_threads;
	case CR_STATE_RESTORE_CREDS:
		return task_entries->nr_threads;
	}

	BUG();
	return -1;
}

static inline int stage_current_participants(int next_stage)
{
	switch (next_stage) {
	case CR_STATE_FORKING:
		return 1;
	case CR_STATE_RESTORE:
		/*
		 * Each thread has to be reported about this stage,
		 * so if we want to wait all other tast, we have to
		 * exclude all threads of the current process.
		 * It is supposed that we will wait other tasks,
		 * before creating threads of the current task.
		 */
		return current->nr_threads;
	}

	BUG();
	return -1;
}

static int __restore_wait_inprogress_tasks(int participants)
{
	int ret;
	futex_t *np = &task_entries->nr_in_progress;

	futex_wait_while_gt(np, participants);
	ret = (int)futex_get(np);
	if (ret < 0) {
		set_cr_errno(get_task_cr_err());
		return ret;
	}

	return 0;
}

static int restore_wait_inprogress_tasks()
{
	return __restore_wait_inprogress_tasks(0);
}

/* Wait all tasks except the current one */
static int restore_wait_other_tasks()
{
	int participants, stage;

	stage = futex_get(&task_entries->start);
	participants = stage_current_participants(stage);

	return __restore_wait_inprogress_tasks(participants);
}

static inline void __restore_switch_stage_nw(int next_stage)
{
	futex_set(&task_entries->nr_in_progress,
			stage_participants(next_stage));
	futex_set(&task_entries->start, next_stage);
}

static inline void __restore_switch_stage(int next_stage)
{
	if (next_stage != CR_STATE_COMPLETE)
		futex_set(&task_entries->nr_in_progress,
				stage_participants(next_stage));
	futex_set_and_wake(&task_entries->start, next_stage);
}

static int restore_switch_stage(int next_stage)
{
	__restore_switch_stage(next_stage);
	return restore_wait_inprogress_tasks();
}

static int restore_finish_ns_stage(int from, int to)
{
	if (root_ns_mask)
		return restore_finish_stage(task_entries, from);

	/* Nobody waits for this stage change, just go ahead */
	__restore_switch_stage_nw(to);
	return 0;
}

static int crtools_prepare_shared(void)
{
	if (prepare_files())
		return -1;

	/* We might want to remove ghost files on failed restore */
	if (collect_remaps_and_regfiles())
		return -1;

	/* Connections are unlocked from criu */
	if (!files_collected() && collect_image(&inet_sk_cinfo))
		return -1;

	if (collect_binfmt_misc())
		return -1;

	if (tty_prep_fds())
		return -1;

	if (prepare_cgroup())
		return -1;

	return 0;
}

/*
 * Collect order information:
 * - reg_file should be before remap, as the latter needs
 *   to find file_desc objects
 * - per-pid collects (mm and fd) should be after remap and
 *   reg_file since both per-pid ones need to get fdesc-s
 *   and bump counters on remaps if they exist
 */

static struct collect_image_info *cinfos[] = {
	&file_locks_cinfo,
	&pipe_data_cinfo,
	&fifo_data_cinfo,
	&sk_queues_cinfo,
};

static struct collect_image_info *cinfos_files[] = {
	&unix_sk_cinfo,
	&fifo_cinfo,
	&pipe_cinfo,
	&nsfile_cinfo,
	&packet_sk_cinfo,
	&netlink_sk_cinfo,
	&eventfd_cinfo,
	&epoll_cinfo,
	&epoll_tfd_cinfo,
	&signalfd_cinfo,
	&tunfile_cinfo,
	&timerfd_cinfo,
	&inotify_cinfo,
	&inotify_mark_cinfo,
	&fanotify_cinfo,
	&fanotify_mark_cinfo,
	&ext_file_cinfo,
};

/* These images are requered to restore namespaces */
static struct collect_image_info *before_ns_cinfos[] = {
	&tty_info_cinfo, /* Restore devpts content */
	&tty_cdata,
};

static struct pprep_head *post_prepare_heads = NULL;

void add_post_prepare_cb(struct pprep_head *ph)
{
	ph->next = post_prepare_heads;
	post_prepare_heads = ph;
}

static int run_post_prepare(void)
{
	struct pprep_head *ph;

	for (ph = post_prepare_heads; ph != NULL; ph = ph->next)
		if (ph->actor(ph))
			return -1;

	return 0;
}

static int root_prepare_shared(void)
{
	int ret = 0;
	struct pstree_item *pi;

	pr_info("Preparing info about shared resources\n");

	if (prepare_remaps())
		return -1;

	if (prepare_seccomp_filters())
		return -1;

	if (collect_images(cinfos, ARRAY_SIZE(cinfos)))
		return -1;

	if (!files_collected() &&
			collect_images(cinfos_files, ARRAY_SIZE(cinfos_files)))
		return -1;

	for_each_pstree_item(pi) {
		if (pi->pid->state == TASK_HELPER)
			continue;

		ret = prepare_mm_pid(pi);
		if (ret < 0)
			break;

		ret = prepare_fd_pid(pi);
		if (ret < 0)
			break;

		ret = prepare_fs_pid(pi);
		if (ret < 0)
			break;
	}

	if (ret < 0)
		goto err;

	prepare_cow_vmas();

	ret = prepare_restorer_blob();
	if (ret)
		goto err;

	/*
	 * This should be called with all packets collected AND all
	 * fdescs and fles prepared BUT post-prep-s not run.
	 */
	ret = prepare_scms();
	if (ret)
		goto err;

	ret = run_post_prepare();
	if (ret)
		goto err;

	show_saved_files();
err:
	return ret;
}

static rt_sigaction_t sigchld_act;
/*
 * If parent's sigaction has blocked SIGKILL (which is non-sence),
 * this parent action is non-valid and shouldn't be inherited.
 * Used to mark parent_act* no more valid.
 */
static rt_sigaction_t parent_act[SIGMAX];
#ifdef CONFIG_COMPAT
static rt_sigaction_t_compat parent_act_compat[SIGMAX];
#endif

static bool sa_inherited(int sig, rt_sigaction_t *sa)
{
	rt_sigaction_t *pa;
	int i;

	if (current == root_item)
		return false; /* XXX -- inherit from CRIU? */

	pa = &parent_act[sig];

	/* Omitting non-valid sigaction */
	if (pa->rt_sa_mask.sig[0] & (1 << SIGKILL))
		return false;

	for (i = 0; i < _KNSIG_WORDS; i++)
		if (pa->rt_sa_mask.sig[i] != sa->rt_sa_mask.sig[i])
			return false;

	return pa->rt_sa_handler == sa->rt_sa_handler &&
		pa->rt_sa_flags == sa->rt_sa_flags &&
		pa->rt_sa_restorer == sa->rt_sa_restorer;
}

static int restore_native_sigaction(int sig, SaEntry *e)
{
	rt_sigaction_t act;
	int ret;

	ASSIGN_TYPED(act.rt_sa_handler, decode_pointer(e->sigaction));
	ASSIGN_TYPED(act.rt_sa_flags, e->flags);
	ASSIGN_TYPED(act.rt_sa_restorer, decode_pointer(e->restorer));
	BUILD_BUG_ON(sizeof(e->mask) != sizeof(act.rt_sa_mask.sig));
	memcpy(act.rt_sa_mask.sig, &e->mask, sizeof(act.rt_sa_mask.sig));

	if (sig == SIGCHLD) {
		sigchld_act = act;
		return 0;
	}

	if (sa_inherited(sig - 1, &act))
		return 1;

	/*
	 * A pure syscall is used, because glibc
	 * sigaction overwrites se_restorer.
	 */
	ret = syscall(SYS_rt_sigaction, sig, &act, NULL, sizeof(k_rtsigset_t));
	if (ret < 0) {
		pr_perror("Can't restore sigaction");
		return ret;
	}

	parent_act[sig - 1] = act;
	/* Mark SIGKILL blocked which makes compat sigaction non-valid */
#ifdef CONFIG_COMPAT
	parent_act_compat[sig - 1].rt_sa_mask.sig[0] |= 1 << SIGKILL;
#endif

	return 1;
}

static void *stack32;

#ifdef CONFIG_COMPAT
static bool sa_compat_inherited(int sig, rt_sigaction_t_compat *sa)
{
	rt_sigaction_t_compat *pa;
	int i;

	if (current == root_item)
		return false;

	pa = &parent_act_compat[sig];

	/* Omitting non-valid sigaction */
	if (pa->rt_sa_mask.sig[0] & (1 << SIGKILL))
		return false;

	for (i = 0; i < _KNSIG_WORDS; i++)
		if (pa->rt_sa_mask.sig[i] != sa->rt_sa_mask.sig[i])
			return false;

	return pa->rt_sa_handler == sa->rt_sa_handler &&
		pa->rt_sa_flags == sa->rt_sa_flags &&
		pa->rt_sa_restorer == sa->rt_sa_restorer;
}

static int restore_compat_sigaction(int sig, SaEntry *e)
{
	rt_sigaction_t_compat act;
	int ret;

	ASSIGN_TYPED(act.rt_sa_handler, (u32)e->sigaction);
	ASSIGN_TYPED(act.rt_sa_flags, e->flags);
	ASSIGN_TYPED(act.rt_sa_restorer, (u32)e->restorer);
	BUILD_BUG_ON(sizeof(e->mask) != sizeof(act.rt_sa_mask.sig));
	memcpy(act.rt_sa_mask.sig, &e->mask, sizeof(act.rt_sa_mask.sig));

	if (sig == SIGCHLD) {
		memcpy(&sigchld_act, &act, sizeof(rt_sigaction_t_compat));
		return 0;
	}

	if (sa_compat_inherited(sig - 1, &act))
		return 1;

	if (!stack32) {
		stack32 = alloc_compat_syscall_stack();
		if (!stack32)
			return -1;
	}

	ret = arch_compat_rt_sigaction(stack32, sig, &act);
	if (ret < 0) {
		pr_err("Can't restore compat sigaction: %d\n", ret);
		return ret;
	}

	parent_act_compat[sig - 1] = act;
	/* Mark SIGKILL blocked which makes native sigaction non-valid */
	parent_act[sig - 1].rt_sa_mask.sig[0] |= 1 << SIGKILL;

	return 1;
}
#else
static int restore_compat_sigaction(int sig, SaEntry *e)
{
	return -1;
}
#endif

static int prepare_sigactions_from_core(TaskCoreEntry *tc)
{
	int sig, i;

	if (tc->n_sigactions != SIGMAX - 2) {
		pr_err("Bad number of sigactions in the image (%d, want %d)\n",
				(int)tc->n_sigactions, SIGMAX - 2);
		return -1;
	}

	pr_info("Restore on-core sigactions for %d\n", vpid(current));

	for (sig = 1, i = 0; sig <= SIGMAX; sig++) {
		int ret;
		SaEntry *e;
		bool sigaction_is_compat;

		if (sig == SIGKILL || sig == SIGSTOP)
			continue;

		e = tc->sigactions[i++];
		sigaction_is_compat = e->has_compat_sigaction && e->compat_sigaction;
		if (sigaction_is_compat)
			ret = restore_compat_sigaction(sig, e);
		else
			ret = restore_native_sigaction(sig, e);

		if (ret < 0)
			return ret;
	}

	return 0;
}

/* Returns number of restored signals, -1 or negative errno on fail */
static int restore_one_sigaction(int sig, struct cr_img *img, int pid)
{
	bool sigaction_is_compat;
	SaEntry *e;
	int ret = 0;

	BUG_ON(sig == SIGKILL || sig == SIGSTOP);

	ret = pb_read_one_eof(img, &e, PB_SIGACT);
	if (ret == 0) {
		if (sig != SIGMAX_OLD + 1) { /* backward compatibility */
			pr_err("Unexpected EOF %d\n", sig);
			return -1;
		}
		pr_warn("This format of sigacts-%d.img is deprecated\n", pid);
		return -1;
	}
	if (ret < 0)
		return ret;

	sigaction_is_compat = e->has_compat_sigaction && e->compat_sigaction;
	if (sigaction_is_compat)
		ret = restore_compat_sigaction(sig, e);
	else
		ret = restore_native_sigaction(sig, e);

	sa_entry__free_unpacked(e, NULL);

	return ret;
}

static int prepare_sigactions_from_image(void)
{
	int pid = vpid(current);
	struct cr_img *img;
	int sig, rst = 0;
	int ret = 0;

	pr_info("Restore sigacts for %d\n", pid);

	img = open_image(CR_FD_SIGACT, O_RSTR, pid);
	if (!img)
		return -1;

	for (sig = 1; sig <= SIGMAX; sig++) {
		if (sig == SIGKILL || sig == SIGSTOP)
			continue;

		ret = restore_one_sigaction(sig, img, pid);
		if (ret < 0)
			break;
		if (ret)
			rst++;
	}

	pr_info("Restored %d/%d sigacts\n", rst,
			SIGMAX - 3 /* KILL, STOP and CHLD */);

	close_image(img);
	return ret;
}

static int prepare_sigactions(CoreEntry *core)
{
	int ret;

	if (!task_alive(current))
		return 0;

	if (core->tc->n_sigactions != 0)
		ret = prepare_sigactions_from_core(core->tc);
	else
		ret = prepare_sigactions_from_image();

	if (stack32) {
		free_compat_syscall_stack(stack32);
		stack32 = NULL;
	}

	return ret;
}

static int __collect_child_pids(struct pstree_item *p, int state, unsigned int *n)
{
	struct pstree_item *pi;

	list_for_each_entry(pi, &p->children, sibling) {
		pid_t *child;

		if (pi->pid->state != state)
			continue;

		child = rst_mem_alloc(sizeof(*child), RM_PRIVATE);
		if (!child)
			return -1;

		(*n)++;
		*child = vpid(pi);
	}

	return 0;
}

static int collect_child_pids(int state, unsigned int *n)
{
	struct pstree_item *pi;

	*n = 0;

	/*
	 * All children of helpers and zombies will be reparented to the init
	 * process and they have to be collected too.
	 */

	if (current == root_item) {
		for_each_pstree_item(pi) {
			if (pi->pid->state != TASK_HELPER &&
			    pi->pid->state != TASK_DEAD)
				continue;
			if (__collect_child_pids(pi, state, n))
				return -1;
		}
	}

	return __collect_child_pids(current, state, n);
}

static int collect_helper_pids(struct task_restore_args *ta)
{
	ta->helpers = (pid_t *)rst_mem_align_cpos(RM_PRIVATE);
	return collect_child_pids(TASK_HELPER, &ta->helpers_n);
}

static int collect_zombie_pids(struct task_restore_args *ta)
{
	ta->zombies = (pid_t *)rst_mem_align_cpos(RM_PRIVATE);
	return collect_child_pids(TASK_DEAD, &ta->zombies_n);
}

static int open_core(int pid, CoreEntry **pcore)
{
	int ret;
	struct cr_img *img;

	img = open_image(CR_FD_CORE, O_RSTR, pid);
	if (!img) {
		pr_err("Can't open core data for %d\n", pid);
		return -1;
	}

	ret = pb_read_one(img, pcore, PB_CORE);
	close_image(img);

	return ret <= 0 ? -1 : 0;
}

static int open_cores(int pid, CoreEntry *leader_core)
{
	int i, tpid;
	CoreEntry **cores = NULL;

	cores = xmalloc(sizeof(*cores)*current->nr_threads);
	if (!cores)
		goto err;

	for (i = 0; i < current->nr_threads; i++) {
		tpid = current->threads[i].ns[0].virt;

		if (tpid == pid)
			cores[i] = leader_core;
		else if (open_core(tpid, &cores[i]))
			goto err;
	}

	current->core = cores;

	return 0;
err:
	xfree(cores);
	return -1;
}

static int prepare_oom_score_adj(int value)
{
	int fd, ret = 0;
	char buf[11];

	fd = open_proc_rw(PROC_SELF, "oom_score_adj");
	if (fd < 0)
		return -1;

	snprintf(buf, 11, "%d", value);

	if (write(fd, buf, 11) < 0) {
		pr_perror("Write %s to /proc/self/oom_score_adj failed", buf);
		ret = -1;
	}

	close(fd);
	return ret;
}

static int prepare_proc_misc(pid_t pid, TaskCoreEntry *tc)
{
	int ret;

	/* loginuid value is critical to restore */
	if (kdat.luid == LUID_FULL && tc->has_loginuid &&
			tc->loginuid != INVALID_UID) {
		ret = prepare_loginuid(tc->loginuid, LOG_ERROR);
		if (ret < 0)
			return ret;
	}

	/* oom_score_adj is not critical: only log errors */
	if (tc->has_oom_score_adj && tc->oom_score_adj != 0)
		prepare_oom_score_adj(tc->oom_score_adj);

	return 0;
}

static int prepare_itimers(int pid, struct task_restore_args *args, CoreEntry *core);
static int prepare_mm(pid_t pid, struct task_restore_args *args);

static int restore_one_alive_task(int pid, CoreEntry *core)
{
	unsigned args_len;
	struct task_restore_args *ta;
	pr_info("Restoring resources\n");

	rst_mem_switch_to_private();

	args_len = round_up(sizeof(*ta) + sizeof(struct thread_restore_args) *
			current->nr_threads, page_size());
	ta = mmap(NULL, args_len, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
	if (!ta)
		return -1;

	memzero(ta, args_len);

	if (prepare_fds(current))
		return -1;

	if (prepare_file_locks(pid))
		return -1;

	if (open_vmas(current))
		return -1;

	if (prepare_aios(current, ta))
		return -1;

	if (fixup_sysv_shmems())
		return -1;

	if (open_cores(pid, core))
		return -1;

	if (prepare_signals(pid, ta, core))
		return -1;

	if (prepare_posix_timers(pid, ta, core))
		return -1;

	if (prepare_rlimits(pid, ta, core) < 0)
		return -1;

	if (collect_helper_pids(ta) < 0)
		return -1;

	if (collect_zombie_pids(ta) < 0)
		return -1;

	if (inherit_fd_fini() < 0)
		return -1;

	if (prepare_proc_misc(pid, core->tc))
		return -1;

	/*
	 * Get all the tcp sockets fds into rst memory -- restorer
	 * will turn repair off before going sigreturn
	 */
	if (prepare_tcp_socks(ta))
		return -1;

	/*
	 * Copy timerfd params for restorer args, we need to proceed
	 * timer setting at the very late.
	 */
	if (prepare_timerfds(ta))
		return -1;

	if (seccomp_filters_get_rst_pos(core, ta) < 0)
		return -1;

	if (prepare_itimers(pid, ta, core) < 0)
		return -1;

	if (prepare_mm(pid, ta))
		return -1;

	if (prepare_vmas(current, ta))
		return -1;

	if (setup_uffd(pid, ta))
		return -1;

	return sigreturn_restore(pid, ta, args_len, core);
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

	for (sig = 1; sig <= SIGMAX; sig++)
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
		(1 << SIGSTKFLT)|\
		(1 << SIGPWR)	 \
	)

static inline int sig_fatal(int sig)
{
	return (sig > 0) && (sig < SIGMAX) && (SIG_FATAL_MASK & (1UL << sig));
}

struct task_entries *task_entries;
static unsigned long task_entries_pos;

static int wait_on_helpers_zombies(void)
{
	struct pstree_item *pi;

	list_for_each_entry(pi, &current->children, sibling) {
		pid_t pid = vpid(pi);
		int status;

		switch (pi->pid->state) {
		case TASK_DEAD:
			if (waitid(P_PID, pid, NULL, WNOWAIT | WEXITED) < 0) {
				pr_perror("Wait on %d zombie failed", pid);
				return -1;
			}
			break;
		case TASK_HELPER:
			if (waitpid(pid, &status, 0) != pid) {
				pr_perror("waitpid for helper %d failed", pid);
				return -1;
			}
			break;
		}
	}

	return 0;
}

static int restore_one_zombie(CoreEntry *core)
{
	int exit_code = core->tc->exit_code;

	pr_info("Restoring zombie with %d code\n", exit_code);

	if (inherit_fd_fini() < 0)
		return -1;

	if (lazy_pages_setup_zombie(vpid(current)))
		return -1;

	prctl(PR_SET_NAME, (long)(void *)core->tc->comm, 0, 0, 0);

	if (task_entries != NULL) {
		restore_finish_stage(task_entries, CR_STATE_RESTORE);
		zombie_prepare_signals();
	}

	if (exit_code & 0x7f) {
		int signr;

		/* prevent generating core files */
		if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0))
			pr_perror("Can't drop the dumpable flag");

		signr = exit_code & 0x7F;
		if (!sig_fatal(signr)) {
			pr_warn("Exit with non fatal signal ignored\n");
			signr = SIGABRT;
		}

		if (kill(vpid(current), signr) < 0)
			pr_perror("Can't kill myself, will just exit");

		exit_code = 0;
	}

	exit((exit_code >> 8) & 0x7f);

	/* never reached */
	BUG_ON(1);
	return -1;
}

static int check_core(CoreEntry *core, struct pstree_item *me)
{
	int ret = -1;

	if (core->mtype != CORE_ENTRY__MARCH) {
		pr_err("Core march mismatch %d\n", (int)core->mtype);
		goto out;
	}

	if (!core->tc) {
		pr_err("Core task state data missed\n");
		goto out;
	}

	if (core->tc->task_state != TASK_DEAD) {
		if (!core->ids && !me->ids) {
			pr_err("Core IDS data missed for non-zombie\n");
			goto out;
		}

		if (!CORE_THREAD_ARCH_INFO(core)) {
			pr_err("Core info data missed for non-zombie\n");
			goto out;
		}
	}

	ret = 0;
out:
	return ret;
}

/*
 * Find if there are children which are zombies or helpers - processes
 * which are expected to die during the restore.
 */
static bool child_death_expected(void)
{
	struct pstree_item *pi;

	list_for_each_entry(pi, &current->children, sibling) {
		switch (pi->pid->state) {
		case TASK_DEAD:
		case TASK_HELPER:
			return true;
		}
	}

	return false;
}

/*
 * Restore a helper process - artificially created by criu
 * to restore attributes of process tree.
 * - sessions for each leaders are dead
 * - process groups with dead leaders
 * - dead tasks for which /proc/<pid>/... is opened by restoring task
 * - whatnot
 */
static int restore_one_helper(void)
{
	siginfo_t info;

	if (!child_death_expected()) {
		/*
		 * Restoree has no children that should die, during restore,
		 * wait for the next stage on futex.
		 * The default SIGCHLD handler will handle an unexpected
		 * child's death and abort the restore if someone dies.
		 */
		restore_finish_stage(task_entries, CR_STATE_RESTORE);
		return 0;
	}

	/*
	 * The restoree has children which will die - decrement itself from
	 * nr. of tasks processing the stage and wait for anyone to die.
	 * Tasks may die only when they're on the following stage.
	 * If one dies earlier - that's unexpected - treat it as an error
	 * and abort the restore.
	 */
	if (block_sigmask(NULL, SIGCHLD))
		return -1;

	/* Finish CR_STATE_RESTORE, but do not wait for the next stage. */
	futex_dec_and_wake(&task_entries->nr_in_progress);

	if (waitid(P_ALL, 0, &info, WEXITED | WNOWAIT)) {
		pr_perror("Failed to wait\n");
		return -1;
	}

	if (futex_get(&task_entries->start) == CR_STATE_RESTORE) {
		pr_err("Child %d died too early\n", info.si_pid);
		return -1;
	}

	if (wait_on_helpers_zombies()) {
		pr_err("Failed to wait on helpers and zombies\n");
		return -1;
	}

	return 0;
}

static int restore_one_task(int pid, CoreEntry *core)
{
	int ret;

	/* No more fork()-s => no more per-pid logs */

	if (task_alive(current))
		ret = restore_one_alive_task(pid, core);
	else if (current->pid->state == TASK_DEAD)
		ret = restore_one_zombie(core);
	else if (current->pid->state == TASK_HELPER) {
		ret = restore_one_helper();
	} else {
		pr_err("Unknown state in code %d\n", (int)core->tc->task_state);
		ret = -1;
	}

	if (core)
		core_entry__free_unpacked(core, NULL);
	return ret;
}

/* All arguments should be above stack, because it grows down */
struct cr_clone_arg {
	struct pstree_item *item;
	unsigned long clone_flags;
	int fd;

	CoreEntry *core;
};

static void maybe_clone_parent(struct pstree_item *item,
			      struct cr_clone_arg *ca)
{
	/*
	 * zdtm runs in kernel 3.11, which has the problem described below. We
	 * avoid this by including the pdeath_sig test. Once users/zdtm migrate
	 * off of 3.11, this condition can be simplified to just test the
	 * options and not have the pdeath_sig test.
	 */
	if (opts.restore_sibling) {
		/*
		 * This means we're called from lib's criu_restore_child().
		 * In that case create the root task as the child one to+
		 * the caller. This is the only way to correctly restore the
		 * pdeath_sig of the root task. But also looks nice.
		 *
		 * Alternatively, if we are --restore-detached, a similar trick is
		 * needed to correctly restore pdeath_sig and prevent processes from
		 * dying once restored.
		 *
		 * There were a problem in kernel 3.11 -- CLONE_PARENT can't be
		 * set together with CLONE_NEWPID, which has been solved in further
		 * versions of the kernels, but we treat 3.11 as a base, so at
		 * least warn a user about potential problems.
		 */
		rsti(item)->clone_flags |= CLONE_PARENT;
		if (rsti(item)->clone_flags & CLONE_NEWPID)
			pr_warn("Set CLONE_PARENT | CLONE_NEWPID but it might cause restore problem,"
				"because not all kernels support such clone flags combinations!\n");
	} else if (opts.restore_detach) {
		if (ca->core->thread_core->pdeath_sig)
			pr_warn("Root task has pdeath_sig configured, so it will receive one _right_"
				"after restore on CRIU exit\n");
	}
}

static inline int fork_with_pid(struct pstree_item *item)
{
	struct cr_clone_arg ca;
	int ret = -1;
	pid_t pid = vpid(item);

	if (item->pid->state != TASK_HELPER) {
		if (open_core(pid, &ca.core))
			return -1;

		if (check_core(ca.core, item))
			return -1;

		item->pid->state = ca.core->tc->task_state;
		rsti(item)->cg_set = ca.core->tc->cg_set;

		rsti(item)->has_seccomp = ca.core->tc->seccomp_mode != SECCOMP_MODE_DISABLED;

		if (item->pid->state != TASK_DEAD && !task_alive(item)) {
			pr_err("Unknown task state %d\n", item->pid->state);
			return -1;
		}

		if (unlikely(item == root_item))
			maybe_clone_parent(item, &ca);
	} else {
		/*
		 * Helper entry will not get moved around and thus
		 * will live in the parent's cgset.
		 */
		rsti(item)->cg_set = rsti(item->parent)->cg_set;
		ca.core = NULL;
	}

	ret = -1;

	ca.item = item;
	ca.clone_flags = rsti(item)->clone_flags;

	BUG_ON(ca.clone_flags & CLONE_VM);

	pr_info("Forking task with %d pid (flags 0x%lx)\n", pid, ca.clone_flags);

	if (!(ca.clone_flags & CLONE_NEWPID)) {
		char buf[32];
		int len;

		ca.fd = open_proc_rw(PROC_GEN, LAST_PID_PATH);
		if (ca.fd < 0)
			goto err;

		if (flock(ca.fd, LOCK_EX)) {
			close(ca.fd);
			pr_perror("%d: Can't lock %s", pid, LAST_PID_PATH);
			goto err;
		}

		len = snprintf(buf, sizeof(buf), "%d", pid - 1);
		if (write(ca.fd, buf, len) != len) {
			pr_perror("%d: Write %s to %s", pid, buf, LAST_PID_PATH);
			goto err_unlock;
		}
	} else {
		ca.fd = -1;
		BUG_ON(pid != INIT_PID);
	}

	/*
	 * Some kernel modules, such as netwrok packet generator
	 * run kernel thread upon net-namespace creattion taking
	 * the @pid we've been requeting via LAST_PID_PATH interface
	 * so that we can't restore a take with pid needed.
	 *
	 * Here is an idea -- unhare net namespace in callee instead.
	 */
	/*
	 * The cgroup namespace is also unshared explicitly in the
	 * move_in_cgroup(), so drop this flag here as well.
	 */
	ret = clone_noasan(restore_task_with_children,
			(ca.clone_flags & ~(CLONE_NEWNET | CLONE_NEWCGROUP)) | SIGCHLD, &ca);
	if (ret < 0) {
		pr_perror("Can't fork for %d", pid);
		goto err_unlock;
	}


	if (item == root_item) {
		item->pid->real = ret;
		pr_debug("PID: real %d virt %d\n",
				item->pid->real, vpid(item));
	}

err_unlock:
	if (ca.fd >= 0) {
		if (flock(ca.fd, LOCK_UN))
			pr_perror("%d: Can't unlock %s", pid, LAST_PID_PATH);

		close(ca.fd);
	}
err:
	if (ca.core)
		core_entry__free_unpacked(ca.core, NULL);
	return ret;
}

static void sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	int status, pid, exit;

	while (1) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid <= 0)
			return;

		if (!current && WIFSTOPPED(status) &&
					WSTOPSIG(status) == SIGCHLD) {
			/* The root task is ptraced. Allow it to handle SIGCHLD */
			ptrace(PTRACE_CONT, siginfo->si_pid, 0, SIGCHLD);
			return;
		}

		exit = WIFEXITED(status);
		status = exit ? WEXITSTATUS(status) : WTERMSIG(status);

		break;
	}

	if (exit)
		pr_err("%d exited, status=%d\n", pid, status);
	else
		pr_err("%d killed by signal %d: %s\n",
			pid, status, strsignal(status));

	futex_abort_and_wake(&task_entries->nr_in_progress);
}

static int criu_signals_setup(void)
{
	int ret;
	struct sigaction act;
	sigset_t blockmask;

	ret = sigaction(SIGCHLD, NULL, &act);
	if (ret < 0) {
		pr_perror("sigaction() failed");
		return -1;
	}

	act.sa_flags |= SA_NOCLDSTOP | SA_SIGINFO | SA_RESTART;
	act.sa_sigaction = sigchld_handler;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGCHLD);

	ret = sigaction(SIGCHLD, &act, NULL);
	if (ret < 0) {
		pr_perror("sigaction() failed");
		return -1;
	}

	/*
	 * The block mask will be restored in sigreturn.
	 *
	 * TODO: This code should be removed, when a freezer will be added.
	 */
	sigfillset(&blockmask);
	sigdelset(&blockmask, SIGCHLD);

	/*
	 * Here we use SIG_SETMASK instead of SIG_BLOCK to avoid the case where
	 * we've been forked from a parent who had blocked SIGCHLD. If SIGCHLD
	 * is blocked when a task dies (e.g. if the task fails to restore
	 * somehow), we hang because our SIGCHLD handler is never run. Since we
	 * depend on SIGCHLD being unblocked, let's set the mask explicitly.
	 */
	ret = sigprocmask(SIG_SETMASK, &blockmask, NULL);
	if (ret < 0) {
		pr_perror("Can't block signals");
		return -1;
	}

	return 0;
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

	if (vpid(current) == current->sid) {
		pr_info("Restoring %d to %d sid\n", vpid(current), current->sid);
		sid = setsid();
		if (sid != current->sid) {
			pr_perror("Can't restore sid (%d)", sid);
			exit(1);
		}
	} else {
		sid = getsid(getpid());
		if (sid != current->sid) {
			/* Skip the root task if it's not init */
			if (current == root_item && vpid(root_item) != INIT_PID)
				return;
			pr_err("Requested sid %d doesn't match inherited %d\n",
					current->sid, sid);
			exit(1);
		}
	}
}

static void restore_pgid(void)
{
	/*
	 * Unlike sessions, process groups (a.k.a. pgids) can be joined
	 * by any task, provided the task with pid == pgid (group leader)
	 * exists. Thus, in order to restore pgid we must make sure that
	 * group leader was born and created the group, then join one.
	 *
	 * We do this _before_ finishing the forking stage to make sure
	 * helpers are still with us.
	 */

	pid_t pgid, my_pgid = current->pgid;

	pr_info("Restoring %d to %d pgid\n", vpid(current), my_pgid);

	pgid = getpgrp();
	if (my_pgid == pgid)
		return;

	if (my_pgid != vpid(current)) {
		struct pstree_item *leader;

		/*
		 * Wait for leader to become such.
		 * Missing leader means we're going to crtools
		 * group (-j option).
		 */

		leader = rsti(current)->pgrp_leader;
		if (leader) {
			BUG_ON(my_pgid != vpid(leader));
			futex_wait_until(&rsti(leader)->pgrp_set, 1);
		}
	}

	pr_info("\twill call setpgid, mine pgid is %d\n", pgid);
	if (setpgid(0, my_pgid) != 0) {
		pr_perror("Can't restore pgid (%d/%d->%d)", vpid(current), pgid, current->pgid);
		exit(1);
	}

	if (my_pgid == vpid(current))
		futex_set_and_wake(&rsti(current)->pgrp_set, 1);
}

static int mount_proc(void)
{
	int fd, ret;
	char proc_mountpoint[] = "crtools-proc.XXXXXX";

	if (root_ns_mask == 0)
		fd = ret = open("/proc", O_DIRECTORY);
	else {
		if (mkdtemp(proc_mountpoint) == NULL) {
			pr_perror("mkdtemp failed %s", proc_mountpoint);
			return -1;
		}

		pr_info("Mount procfs in %s\n", proc_mountpoint);
		if (mount("proc", proc_mountpoint, "proc", MS_MGC_VAL | MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL)) {
			pr_perror("mount failed");
			rmdir(proc_mountpoint);
			return -1;
		}

		ret = fd = open_detach_mount(proc_mountpoint);
	}

	if (fd >= 0) {
		ret = set_proc_fd(fd);
		close(fd);
	}

	return ret;
}

/*
 * Tasks cannot change sid (session id) arbitrary, but can either
 * inherit one from ancestor, or create a new one with id equal to
 * their pid. Thus sid-s restore is tied with children creation.
 */

static int create_children_and_session(void)
{
	int ret;
	struct pstree_item *child;

	pr_info("Restoring children in alien sessions:\n");
	list_for_each_entry(child, &current->children, sibling) {
		if (!restore_before_setsid(child))
			continue;

		BUG_ON(child->born_sid != -1 && getsid(getpid()) != child->born_sid);

		ret = fork_with_pid(child);
		if (ret < 0)
			return ret;
	}

	if (current->parent)
		restore_sid();

	pr_info("Restoring children in our session:\n");
	list_for_each_entry(child, &current->children, sibling) {
		if (restore_before_setsid(child))
			continue;

		ret = fork_with_pid(child);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int restore_task_with_children(void *_arg)
{
	struct cr_clone_arg *ca = _arg;
	pid_t pid;
	int ret;

	current = ca->item;

	if (current != root_item) {
		char buf[12];
		int fd;

		/* Determine PID in CRIU's namespace */
		fd = get_service_fd(CR_PROC_FD_OFF);
		if (fd < 0)
			goto err;

		ret = readlinkat(fd, "self", buf, sizeof(buf) - 1);
		if (ret < 0) {
			pr_perror("Unable to read the /proc/self link");
			goto err;
		}
		buf[ret] = '\0';

		current->pid->real = atoi(buf);
		pr_debug("PID: real %d virt %d\n",
				current->pid->real, vpid(current));
	}

	if ( !(ca->clone_flags & CLONE_FILES))
		close_safe(&ca->fd);

	if (current->pid->state != TASK_HELPER) {
		ret = clone_service_fd(rsti(current)->service_fd_id);
		if (ret)
			goto err;
	}

	pid = getpid();
	if (vpid(current) != pid) {
		pr_err("Pid %d do not match expected %d\n", pid, vpid(current));
		set_task_cr_err(EEXIST);
		goto err;
	}

	ret = log_init_by_pid();
	if (ret < 0)
		goto err;

	if (ca->clone_flags & CLONE_NEWNET) {
		ret = unshare(CLONE_NEWNET);
		if (ret) {
			pr_perror("Can't unshare net-namespace");
			goto err;
		}
	}

	if (!(ca->clone_flags & CLONE_FILES)) {
		ret = close_old_fds();
		if (ret)
			goto err;
	}

	/* Wait prepare_userns */
	if (current->parent == NULL &&
			restore_finish_ns_stage(CR_STATE_ROOT_TASK, CR_STATE_PREPARE_NAMESPACES) < 0)
		goto err;

	/*
	 * Call this _before_ forking to optimize cgroups
	 * restore -- if all tasks live in one set of cgroups
	 * we will only move the root one there, others will
	 * just have it inherited.
	 */
	if (prepare_task_cgroup(current) < 0)
		goto err;

	/* Restore root task */
	if (current->parent == NULL) {
		if (fdstore_init())
			goto err;

		if (join_namespaces()) {
			pr_perror("Join namespaces failed");
			goto err;
		}

		pr_info("Calling restore_sid() for init\n");
		restore_sid();

		/*
		 * We need non /proc proc mount for restoring pid and mount
		 * namespaces and do not care for the rest of the cases.
		 * Thus -- mount proc at custom location for any new namespace
		 */
		if (mount_proc())
			goto err;

		if (!files_collected() && collect_image(&tty_cinfo))
			goto err;
		if (collect_images(before_ns_cinfos, ARRAY_SIZE(before_ns_cinfos)))
			goto err;

		if (prepare_namespace(current, ca->clone_flags))
			goto err;

		if (restore_finish_ns_stage(CR_STATE_PREPARE_NAMESPACES, CR_STATE_FORKING) < 0)
			goto err;

		if (root_prepare_shared())
			goto err;
	}

	if (restore_task_mnt_ns(current))
		goto err;

	if (prepare_mappings(current))
		goto err;

	if (prepare_sigactions(ca->core) < 0)
		goto err;

	if (fault_injected(FI_RESTORE_ROOT_ONLY)) {
		pr_info("fault: Restore root task failure!\n");
		kill(getpid(), SIGKILL);
	}

	timing_start(TIME_FORK);

	if (create_children_and_session())
		goto err;

	timing_stop(TIME_FORK);

	if (unmap_guard_pages(current))
		goto err;

	restore_pgid();

	if (open_transport_socket())
		return -1;

	if (current->parent == NULL) {
		/*
		 * Wait when all tasks passed the CR_STATE_FORKING stage.
		 * The stage was started by criu, but now it waits for
		 * the CR_STATE_RESTORE to finish. See comment near the
		 * CR_STATE_FORKING macro for details.
		 *
		 * It means that all tasks entered into their namespaces.
		 */
		if (restore_wait_other_tasks())
			goto err;
		fini_restore_mntns();
		__restore_switch_stage(CR_STATE_RESTORE);
	} else {
		if (restore_finish_stage(task_entries, CR_STATE_FORKING) < 0)
			goto err;
	}

	if (restore_one_task(vpid(current), ca->core))
		goto err;

	return 0;

err:
	if (current->parent == NULL)
		futex_abort_and_wake(&task_entries->nr_in_progress);
	exit(1);
}

static int attach_to_tasks(bool root_seized)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		int status, i;

		if (!task_alive(item))
			continue;

		if (item->nr_threads == 1) {
			item->threads[0].real = item->pid->real;
		} else {
			if (parse_threads(item->pid->real, &item->threads, &item->nr_threads))
				return -1;
		}

		for (i = 0; i < item->nr_threads; i++) {
			pid_t pid = item->threads[i].real;

			if (item != root_item || !root_seized || i != 0) {
				if (ptrace(PTRACE_SEIZE, pid, 0, 0)) {
					pr_perror("Can't attach to %d", pid);
					return -1;
				}
			}
			if (ptrace(PTRACE_INTERRUPT, pid, 0, 0)) {
				pr_perror("Can't interrupt the %d task", pid);
				return -1;
			}


			if (wait4(pid, &status, __WALL, NULL) != pid) {
				pr_perror("waitpid(%d) failed", pid);
				return -1;
			}

			/*
			 * Suspend seccomp if necessary. We need to do this because
			 * although seccomp is restored at the very end of the
			 * restorer blob (and the final sigreturn is ok), here we're
			 * doing an munmap in the process, which may be blocked by
			 * seccomp and cause the task to be killed.
			 */
			if (rsti(item)->has_seccomp && ptrace_suspend_seccomp(pid) < 0)
				pr_err("failed to suspend seccomp, restore will probably fail...\n");

			if (ptrace(PTRACE_CONT, pid, NULL, NULL) ) {
				pr_perror("Unable to resume %d", pid);
				return -1;
			}
		}
	}

	return 0;
}

static int catch_tasks(bool root_seized, enum trace_flags *flag)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		int status, i, ret;

		if (!task_alive(item))
			continue;

		if (item->nr_threads == 1) {
			item->threads[0].real = item->pid->real;
		} else {
			if (parse_threads(item->pid->real, &item->threads, &item->nr_threads))
				return -1;
		}

		for (i = 0; i < item->nr_threads; i++) {
			pid_t pid = item->threads[i].real;

			if (ptrace(PTRACE_INTERRUPT, pid, 0, 0)) {
				pr_perror("Can't interrupt the %d task", pid);
				return -1;
			}

			if (wait4(pid, &status, __WALL, NULL) != pid) {
				pr_perror("waitpid(%d) failed", pid);
				return -1;
			}

			ret = compel_stop_pie(pid, rsti(item)->breakpoint,
					flag, fault_injected(FI_NO_BREAKPOINTS));
			if (ret < 0)
				return -1;
		}
	}

	return 0;
}

static int clear_breakpoints()
{
	struct pstree_item *item;
	int ret = 0, i;

	if (fault_injected(FI_NO_BREAKPOINTS))
		return 0;

	for_each_pstree_item(item) {
		if (!task_alive(item))
			continue;
		for (i = 0; i < item->nr_threads; i++)
			ret |= ptrace_flush_breakpoints(item->threads[i].real);
	}

	return ret;
}

static void finalize_restore(void)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		pid_t pid = item->pid->real;
		struct parasite_ctl *ctl;

		if (!task_alive(item))
			continue;

		/* Unmap the restorer blob */
		ctl = compel_prepare_noctx(pid);
		if (ctl == NULL)
			continue;

		compel_unmap(ctl, (unsigned long)rsti(item)->munmap_restorer);

		xfree(ctl);

		if ((item->pid->state == TASK_STOPPED) ||
				(opts.final_state == TASK_STOPPED))
			kill(item->pid->real, SIGSTOP);
	}
}

static void finalize_restore_detach(int status)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		pid_t pid;
		int i;

		if (!task_alive(item))
			continue;

		for (i = 0; i < item->nr_threads; i++) {
			pid = item->threads[i].real;
			if (pid < 0) {
				BUG_ON(status >= 0);
				break;
			}

			if (arch_set_thread_regs_nosigrt(&item->threads[i]))
				pr_perror("Restoring regs for %d failed", pid);
			if (ptrace(PTRACE_DETACH, pid, NULL, 0))
				pr_perror("Unable to execute %d", pid);
		}
	}
}

static void ignore_kids(void)
{
	struct sigaction sa = { .sa_handler = SIG_DFL };

	if (sigaction(SIGCHLD, &sa, NULL) < 0)
		pr_perror("Restoring CHLD sigaction failed");
}

static unsigned int saved_loginuid;

static int prepare_userns_hook(void)
{
	int ret;

	if (kdat.luid != LUID_FULL)
		return 0;
	/*
	 * Save old loginuid and set it to INVALID_UID:
	 * this value means that loginuid is unset and it will be inherited.
	 * After you set some value to /proc/<>/loginuid it can't be changed
	 * inside container due to permissions.
	 * But you still can set this value if it was unset.
	 */
	saved_loginuid = parse_pid_loginuid(getpid(), &ret, false);
	if (ret < 0)
		return -1;

	if (prepare_loginuid(INVALID_UID, LOG_ERROR) < 0) {
		pr_err("Setting loginuid for CT init task failed, CAP_AUDIT_CONTROL?\n");
		return -1;
	}
	return 0;
}

static void restore_origin_ns_hook(void)
{
	if (kdat.luid != LUID_FULL)
		return;

	/* not critical: it does not affect CT in any way */
	if (prepare_loginuid(saved_loginuid, LOG_ERROR) < 0)
		pr_err("Restore original /proc/self/loginuid failed\n");
}

static int write_restored_pid(void)
{
	int pid;

	if (!opts.pidfile)
		return 0;

	pid = root_item->pid->real;

	if (write_pidfile(pid) < 0) {
		pr_perror("Can't write pidfile");
		return -1;
	}

	return 0;
}

static int restore_root_task(struct pstree_item *init)
{
	enum trace_flags flag = TRACE_ALL;
	int ret, fd, mnt_ns_fd = -1;
	int root_seized = 0;
	struct pstree_item *item;

	ret = run_scripts(ACT_PRE_RESTORE);
	if (ret != 0) {
		pr_err("Aborting restore due to pre-restore script ret code %d\n", ret);
		return -1;
	}

	fd = open("/proc", O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		pr_perror("Unable to open /proc");
		return -1;
	}

	ret = install_service_fd(CR_PROC_FD_OFF, fd);
	close(fd);
	if (ret < 0)
		return -1;

	/*
	 * FIXME -- currently we assume that all the tasks live
	 * in the same set of namespaces. This is done to debug
	 * the ns contents dumping/restoring. Need to revisit
	 * this later.
	 */

	if (vpid(init) == INIT_PID) {
		if (!(root_ns_mask & CLONE_NEWPID)) {
			pr_err("This process tree can only be restored "
				"in a new pid namespace.\n"
				"criu should be re-executed with the "
				"\"--namespace pid\" option.\n");
			return -1;
		}
	} else	if (root_ns_mask & CLONE_NEWPID) {
		pr_err("Can't restore pid namespace without the process init\n");
		return -1;
	}

	if (prepare_userns_hook())
		return -1;

	if (prepare_namespace_before_tasks())
		return -1;

	__restore_switch_stage_nw(CR_STATE_ROOT_TASK);

	ret = fork_with_pid(init);
	if (ret < 0)
		goto out;

	restore_origin_ns_hook();

	if (rsti(init)->clone_flags & CLONE_PARENT) {
		struct sigaction act;

		root_seized = 1;
		/*
		 * Root task will be our sibling. This means, that
		 * we will not notice when (if) it dies in SIGCHLD
		 * handler, but we should. To do this -- attach to
		 * the guy with ptrace (below) and (!) make the kernel
		 * deliver us the signal when it will get stopped.
		 * It will in case of e.g. segfault before handling
		 * the signal.
		 */
		sigaction(SIGCHLD, NULL, &act);
		act.sa_flags &= ~SA_NOCLDSTOP;
		sigaction(SIGCHLD, &act, NULL);

		if (ptrace(PTRACE_SEIZE, init->pid->real, 0, 0)) {
			pr_perror("Can't attach to init");
			goto out_kill;
		}
	}

	if (!root_ns_mask)
		goto skip_ns_bouncing;

	/*
	 * uid_map and gid_map must be filled from a parent user namespace.
	 * prepare_userns_creds() must be called after filling mappings.
	 */
	if ((root_ns_mask & CLONE_NEWUSER) && prepare_userns(init))
		goto out_kill;

	pr_info("Wait until namespaces are created\n");
	ret = restore_wait_inprogress_tasks();
	if (ret)
		goto out_kill;

	ret = run_scripts(ACT_SETUP_NS);
	if (ret)
		goto out_kill;

	ret = restore_switch_stage(CR_STATE_PREPARE_NAMESPACES);
	if (ret)
		goto out_kill;

	if (root_ns_mask & CLONE_NEWNS) {
		mnt_ns_fd = open_proc(init->pid->real, "ns/mnt");
		if (mnt_ns_fd < 0)
			goto out_kill;
	}

	if (opts.empty_ns & CLONE_NEWNET) {
		/*
		 * Local TCP connections were locked by network_lock_internal()
		 * on dump and normally should have been C/R-ed by respectively
		 * dump_iptables() and restore_iptables() in net.c. However in
		 * the '--empty-ns net' mode no iptables C/R is done and we
		 * need to return these rules by hands.
		 */
		ret = network_lock_internal();
		if (ret)
			goto out_kill;
	}

	ret = run_scripts(ACT_POST_SETUP_NS);
	if (ret)
		goto out_kill;

	__restore_switch_stage(CR_STATE_FORKING);

skip_ns_bouncing:

	ret = restore_wait_inprogress_tasks();
	if (ret < 0)
		goto out_kill;

	/*
	 * Zombies die after CR_STATE_RESTORE which is switched
	 * by root task, not by us. See comment before CR_STATE_FORKING
	 * in the header for details.
	 */
	for_each_pstree_item(item) {
		if (item->pid->state == TASK_DEAD)
			task_entries->nr_threads--;
	}

	ret = restore_switch_stage(CR_STATE_RESTORE_SIGCHLD);
	if (ret < 0)
		goto out_kill;

	ret = stop_usernsd();
	if (ret < 0)
		goto out_kill;

	ret = move_veth_to_bridge();
	if (ret < 0)
		goto out_kill;

	ret = prepare_cgroup_properties();
	if (ret < 0)
		goto out_kill;

	if (fault_injected(FI_POST_RESTORE))
		goto out_kill;

	ret = run_scripts(ACT_POST_RESTORE);
	if (ret != 0) {
		pr_err("Aborting restore due to post-restore script ret code %d\n", ret);
		timing_stop(TIME_RESTORE);
		write_stats(RESTORE_STATS);
		goto out_kill;
	}

	/*
	 * There is no need to call try_clean_remaps() after this point,
	 * as restore went OK and all ghosts were removed by the openers.
	 */
	if (depopulate_roots_yard(mnt_ns_fd, false))
		goto out_kill;

	close_safe(&mnt_ns_fd);

	if (write_restored_pid())
		goto out_kill;

	/* Unlock network before disabling repair mode on sockets */
	network_unlock();

	/*
	 * Stop getting sigchld, after we resume the tasks they
	 * may start to exit poking criu in vain.
	 */
	ignore_kids();

	/*
	 * -------------------------------------------------------------
	 * Below this line nothing should fail, because network is unlocked
	 */
	attach_to_tasks(root_seized);

	ret = restore_switch_stage(CR_STATE_RESTORE_CREDS);
	BUG_ON(ret);

	timing_stop(TIME_RESTORE);

	ret = catch_tasks(root_seized, &flag);

	if (lazy_pages_finish_restore())
		goto out_kill;

	pr_info("Restore finished successfully. Resuming tasks.\n");
	__restore_switch_stage(CR_STATE_COMPLETE);

	if (ret == 0)
		ret = compel_stop_on_syscall(task_entries->nr_threads,
			__NR(rt_sigreturn, 0), __NR(rt_sigreturn, 1), flag);

	if (clear_breakpoints())
		pr_err("Unable to flush breakpoints\n");

	if (ret == 0)
		finalize_restore();

	ret = run_scripts(ACT_PRE_RESUME);
	if (ret)
		pr_err("Pre-resume script ret code %d\n", ret);

	if (restore_freezer_state())
		pr_err("Unable to restore freezer state\n");

	fini_cgroup();

	/* Detaches from processes and they continue run through sigreturn. */
	finalize_restore_detach(ret);

	write_stats(RESTORE_STATS);

	ret = run_scripts(ACT_POST_RESUME);
	if (ret != 0)
		pr_err("Post-resume script ret code %d\n", ret);

	if (!opts.restore_detach && !opts.exec_cmd)
		wait(NULL);

	return 0;

out_kill:
	/*
	 * The processes can be killed only when all of them have been created,
	 * otherwise an external proccesses can be killed.
	 */
	if (root_ns_mask & CLONE_NEWPID) {
		int status;

		/* Kill init */
		if (root_item->pid->real > 0)
			kill(root_item->pid->real, SIGKILL);

		if (waitpid(root_item->pid->real, &status, 0) < 0)
			pr_warn("Unable to wait %d: %s",
				root_item->pid->real, strerror(errno));
	} else {
		struct pstree_item *pi;

		for_each_pstree_item(pi)
			if (vpid(pi) > 0)
				kill(vpid(pi), SIGKILL);
	}

out:
	fini_cgroup();
	depopulate_roots_yard(mnt_ns_fd, true);
	stop_usernsd();
	__restore_switch_stage(CR_STATE_FAIL);
	pr_err("Restoring FAILED.\n");
	return -1;
}

int prepare_task_entries(void)
{
	task_entries_pos = rst_mem_align_cpos(RM_SHREMAP);
	task_entries = rst_mem_alloc(sizeof(*task_entries), RM_SHREMAP);
	if (!task_entries) {
		pr_perror("Can't map shmem");
		return -1;
	}

	task_entries->nr_threads = 0;
	task_entries->nr_tasks = 0;
	task_entries->nr_helpers = 0;
	futex_set(&task_entries->start, CR_STATE_FAIL);
	mutex_init(&task_entries->userns_sync_lock);

	return 0;
}

int prepare_dummy_task_state(struct pstree_item *pi)
{
	CoreEntry *core;

	if (open_core(vpid(pi), &core))
		return -1;

	pi->pid->state = core->tc->task_state;
	core_entry__free_unpacked(core, NULL);

	return 0;
}

int cr_restore_tasks(void)
{
	int ret = -1;

	if (cr_plugin_init(CR_PLUGIN_STAGE__RESTORE))
		return -1;

	if (check_img_inventory() < 0)
		goto err;

	if (init_stats(RESTORE_STATS))
		goto err;

	if (lsm_check_opts())
		goto err;

	timing_start(TIME_RESTORE);

	if (cpu_init() < 0)
		goto err;

	if (vdso_init_restore())
		goto err;

	if (opts.cpu_cap & (CPU_CAP_INS | CPU_CAP_CPU)) {
		if (cpu_validate_cpuinfo())
			goto err;
	}

	if (prepare_task_entries() < 0)
		goto err;

	if (prepare_pstree() < 0)
		goto err;

	if (crtools_prepare_shared() < 0)
		goto err;

	if (criu_signals_setup() < 0)
		goto err;

	if (prepare_lazy_pages_socket() < 0)
		goto err;

	ret = restore_root_task(root_item);
err:
	cr_plugin_fini(CR_PLUGIN_STAGE__RESTORE, ret);
	return ret;
}

static long restorer_get_vma_hint(struct list_head *tgt_vma_list,
		struct list_head *self_vma_list, long vma_len)
{
	struct vma_area *t_vma, *s_vma;
	long prev_vma_end = 0;
	struct vma_area end_vma;
	VmaEntry end_e;

	end_vma.e = &end_e;
	end_e.start = end_e.end = kdat.task_size;
	prev_vma_end = kdat.mmap_min_addr;

	s_vma = list_first_entry(self_vma_list, struct vma_area, list);
	t_vma = list_first_entry(tgt_vma_list, struct vma_area, list);

	while (1) {
		if (prev_vma_end + vma_len > s_vma->e->start) {
			if (s_vma->list.next == self_vma_list) {
				s_vma = &end_vma;
				continue;
			}
			if (s_vma == &end_vma)
				break;
			if (prev_vma_end < s_vma->e->end)
				prev_vma_end = s_vma->e->end;
			s_vma = vma_next(s_vma);
			continue;
		}

		if (prev_vma_end + vma_len > t_vma->e->start) {
			if (t_vma->list.next == tgt_vma_list) {
				t_vma = &end_vma;
				continue;
			}
			if (t_vma == &end_vma)
				break;
			if (prev_vma_end < t_vma->e->end)
				prev_vma_end = t_vma->e->end;
			t_vma = vma_next(t_vma);
			continue;
		}

		return prev_vma_end;
	}

	return -1;
}

static inline int timeval_valid(struct timeval *tv)
{
	return (tv->tv_sec >= 0) && ((unsigned long)tv->tv_usec < USEC_PER_SEC);
}

static inline int decode_itimer(char *n, ItimerEntry *ie, struct itimerval *val)
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

/*
 * Legacy itimers restore from CR_FD_ITIMERS
 */

static int prepare_itimers_from_fd(int pid, struct task_restore_args *args)
{
	int ret = -1;
	struct cr_img *img;
	ItimerEntry *ie;

	if (!deprecated_ok("Itimers"))
		return -1;

	img = open_image(CR_FD_ITIMERS, O_RSTR, pid);
	if (!img)
		return -1;

	ret = pb_read_one(img, &ie, PB_ITIMER);
	if (ret < 0)
		goto out;
	ret = decode_itimer("real", ie, &args->itimers[0]);
	itimer_entry__free_unpacked(ie, NULL);
	if (ret < 0)
		goto out;

	ret = pb_read_one(img, &ie, PB_ITIMER);
	if (ret < 0)
		goto out;
	ret = decode_itimer("virt", ie, &args->itimers[1]);
	itimer_entry__free_unpacked(ie, NULL);
	if (ret < 0)
		goto out;

	ret = pb_read_one(img, &ie, PB_ITIMER);
	if (ret < 0)
		goto out;
	ret = decode_itimer("prof", ie, &args->itimers[2]);
	itimer_entry__free_unpacked(ie, NULL);
	if (ret < 0)
		goto out;
out:
	close_image(img);
	return ret;
}

static int prepare_itimers(int pid, struct task_restore_args *args, CoreEntry *core)
{
	int ret = 0;
	TaskTimersEntry *tte = core->tc->timers;

	if (!tte)
		return prepare_itimers_from_fd(pid, args);

	ret |= decode_itimer("real", tte->real, &args->itimers[0]);
	ret |= decode_itimer("virt", tte->virt, &args->itimers[1]);
	ret |= decode_itimer("prof", tte->prof, &args->itimers[2]);

	return ret;
}

static inline int timespec_valid(struct timespec *ts)
{
	return (ts->tv_sec >= 0) && ((unsigned long)ts->tv_nsec < NSEC_PER_SEC);
}

static inline int decode_posix_timer(PosixTimerEntry *pte,
		struct restore_posix_timer *pt)
{
	pt->val.it_interval.tv_sec = pte->isec;
	pt->val.it_interval.tv_nsec = pte->insec;

	if (!timespec_valid(&pt->val.it_interval)) {
		pr_err("Invalid timer interval(posix)\n");
		return -1;
	}

	if (pte->vsec == 0 && pte->vnsec == 0) {
		// Remaining time was too short. Set it to
		// interval to make the timer armed and work.
		pt->val.it_value.tv_sec = pte->isec;
		pt->val.it_value.tv_nsec = pte->insec;
	} else {
		pt->val.it_value.tv_sec = pte->vsec;
		pt->val.it_value.tv_nsec = pte->vnsec;
	}

	if (!timespec_valid(&pt->val.it_value)) {
		pr_err("Invalid timer value(posix)\n");
		return -1;
	}

	pt->spt.it_id = pte->it_id;
	pt->spt.clock_id = pte->clock_id;
	pt->spt.si_signo = pte->si_signo;
	pt->spt.it_sigev_notify = pte->it_sigev_notify;
	pt->spt.sival_ptr = decode_pointer(pte->sival_ptr);
	pt->overrun = pte->overrun;

	return 0;
}

static int cmp_posix_timer_proc_id(const void *p1, const void *p2)
{
	return ((struct restore_posix_timer *)p1)->spt.it_id - ((struct restore_posix_timer *)p2)->spt.it_id;
}

static void sort_posix_timers(struct task_restore_args *ta)
{
	void *tmem;

	/*
	 * This is required for restorer's create_posix_timers(),
	 * it will probe them one-by-one for the desired ID, since
	 * kernel doesn't provide another API for timer creation
	 * with given ID.
	 */

	if (ta->posix_timers_n > 0) {
		tmem = rst_mem_remap_ptr((unsigned long)ta->posix_timers, RM_PRIVATE);
		qsort(tmem, ta->posix_timers_n,
				sizeof(struct restore_posix_timer),
				cmp_posix_timer_proc_id);
	}
}

/*
 * Legacy posix timers restoration from CR_FD_POSIX_TIMERS
 */

static int prepare_posix_timers_from_fd(int pid, struct task_restore_args *ta)
{
	struct cr_img *img;
	int ret = -1;
	struct restore_posix_timer *t;

	if (!deprecated_ok("Posix timers"))
		return -1;

	img = open_image(CR_FD_POSIX_TIMERS, O_RSTR, pid);
	if (!img)
		return -1;

	ta->posix_timers_n = 0;
	while (1) {
		PosixTimerEntry *pte;

		ret = pb_read_one_eof(img, &pte, PB_POSIX_TIMER);
		if (ret <= 0)
			break;

		t = rst_mem_alloc(sizeof(struct restore_posix_timer), RM_PRIVATE);
		if (!t)
			break;

		ret = decode_posix_timer(pte, t);
		if (ret < 0)
			break;

		posix_timer_entry__free_unpacked(pte, NULL);
		ta->posix_timers_n++;
	}

	close_image(img);
	if (!ret)
		sort_posix_timers(ta);

	return ret;
}

static int prepare_posix_timers(int pid, struct task_restore_args *ta, CoreEntry *core)
{
	int i, ret = -1;
	TaskTimersEntry *tte = core->tc->timers;
	struct restore_posix_timer *t;

	ta->posix_timers = (struct restore_posix_timer *)rst_mem_align_cpos(RM_PRIVATE);

	if (!tte)
		return prepare_posix_timers_from_fd(pid, ta);

	ta->posix_timers_n = tte->n_posix;
	for (i = 0; i < ta->posix_timers_n; i++) {
		t = rst_mem_alloc(sizeof(struct restore_posix_timer), RM_PRIVATE);
		if (!t)
			goto out;

		if (decode_posix_timer(tte->posix[i], t))
			goto out;
	}

	ret = 0;
	sort_posix_timers(ta);
out:
	return ret;
}

static inline int verify_cap_size(CredsEntry *ce)
{
	return ((ce->n_cap_inh == CR_CAP_SIZE) && (ce->n_cap_eff == CR_CAP_SIZE) &&
		(ce->n_cap_prm == CR_CAP_SIZE) && (ce->n_cap_bnd == CR_CAP_SIZE));
}

static int prepare_mm(pid_t pid, struct task_restore_args *args)
{
	int exe_fd, i, ret = -1;
	MmEntry *mm = rsti(current)->mm;

	args->mm = *mm;
	args->mm.n_mm_saved_auxv = 0;
	args->mm.mm_saved_auxv = NULL;

	if (mm->n_mm_saved_auxv > AT_VECTOR_SIZE) {
		pr_err("Image corrupted on pid %d\n", pid);
		goto out;
	}

	args->mm_saved_auxv_size = mm->n_mm_saved_auxv*sizeof(auxv_t);
	for (i = 0; i < mm->n_mm_saved_auxv; ++i) {
		args->mm_saved_auxv[i] = (auxv_t)mm->mm_saved_auxv[i];
	}

	exe_fd = open_reg_by_id(mm->exe_file_id);
	if (exe_fd < 0)
		goto out;

	args->fd_exe_link = exe_fd;

	args->has_thp_enabled = rsti(current)->has_thp_enabled;

	ret = 0;
out:
	return ret;
}

static void *restorer;
static unsigned long restorer_len;

static int prepare_restorer_blob(void)
{
	/*
	 * We map anonymous mapping, not mremap the restorer itself later.
	 * Otherwise the restorer vma would be tied to criu binary which
	 * in turn will lead to set-exe-file prctl to fail with EBUSY.
	 */

	restorer_len = pie_size(restorer);
	restorer = mmap(NULL, restorer_len,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANON, 0, 0);
	if (restorer == MAP_FAILED) {
		pr_perror("Can't map restorer code");
		return -1;
	}

	memcpy(restorer, &restorer_blob, sizeof(restorer_blob));
	return 0;
}

static int remap_restorer_blob(void *addr)
{
	void *mem;

	mem = mremap(restorer, restorer_len, restorer_len,
			MREMAP_FIXED | MREMAP_MAYMOVE, addr);
	if (mem != addr) {
		pr_perror("Can't remap restorer blob");
		return -1;
	}

	compel_relocs_apply(addr, addr, sizeof(restorer_blob),
			restorer_relocs, ARRAY_SIZE(restorer_relocs));

	return 0;
}

static int validate_sched_parm(struct rst_sched_param *sp)
{
	if ((sp->nice < -20) || (sp->nice > 19))
		return 0;

	switch (sp->policy) {
	case SCHED_RR:
	case SCHED_FIFO:
		return ((sp->prio > 0) && (sp->prio < 100));
	case SCHED_IDLE:
	case SCHED_OTHER:
	case SCHED_BATCH:
		return sp->prio == 0;
	}

	return 0;
}

static int prep_sched_info(struct rst_sched_param *sp, ThreadCoreEntry *tc)
{
	if (!tc->has_sched_policy) {
		sp->policy = SCHED_OTHER;
		sp->nice = 0;
		return 0;
	}

	sp->policy = tc->sched_policy;
	sp->nice = tc->sched_nice;
	sp->prio = tc->sched_prio;

	if (!validate_sched_parm(sp)) {
		pr_err("Inconsistent sched params received (%d.%d.%d)\n",
				sp->policy, sp->nice, sp->prio);
		return -1;
	}

	return 0;
}

static rlim_t decode_rlim(rlim_t ival)
{
	return ival == -1 ? RLIM_INFINITY : ival;
}

/*
 * Legacy rlimits restore from CR_FD_RLIMIT
 */

static int prepare_rlimits_from_fd(int pid, struct task_restore_args *ta)
{
	struct rlimit *r;
	int ret;
	struct cr_img *img;

	if (!deprecated_ok("Rlimits"))
		return -1;

	/*
	 * Old image -- read from the file.
	 */
	img = open_image(CR_FD_RLIMIT, O_RSTR, pid);
	if (!img)
		return -1;

	ta->rlims_n = 0;
	while (1) {
		RlimitEntry *re;

		ret = pb_read_one_eof(img, &re, PB_RLIMIT);
		if (ret <= 0)
			break;

		r = rst_mem_alloc(sizeof(*r), RM_PRIVATE);
		if (!r) {
			pr_err("Can't allocate memory for resource %d\n",
			       ta->rlims_n);
			return -1;
		}

		r->rlim_cur = decode_rlim(re->cur);
		r->rlim_max = decode_rlim(re->max);
		if (r->rlim_cur > r->rlim_max) {
			pr_err("Can't restore cur > max for %d.%d\n",
					pid, ta->rlims_n);
			r->rlim_cur = r->rlim_max;
		}

		rlimit_entry__free_unpacked(re, NULL);

		ta->rlims_n++;
	}

	close_image(img);

	return 0;
}

static int prepare_rlimits(int pid, struct task_restore_args *ta, CoreEntry *core)
{
	int i;
	TaskRlimitsEntry *rls = core->tc->rlimits;
	struct rlimit64 *r;

	ta->rlims = (struct rlimit64 *)rst_mem_align_cpos(RM_PRIVATE);

	if (!rls)
		return prepare_rlimits_from_fd(pid, ta);

	for (i = 0; i < rls->n_rlimits; i++) {
		r = rst_mem_alloc(sizeof(*r), RM_PRIVATE);
		if (!r) {
			pr_err("Can't allocate memory for resource %d\n", i);
			return -1;
		}

		r->rlim_cur = decode_rlim(rls->rlimits[i]->cur);
		r->rlim_max = decode_rlim(rls->rlimits[i]->max);

		if (r->rlim_cur > r->rlim_max) {
			pr_warn("Can't restore cur > max for %d.%d\n", pid, i);
			r->rlim_cur = r->rlim_max;
		}
	}

	ta->rlims_n = rls->n_rlimits;
	return 0;
}

static int signal_to_mem(SiginfoEntry *sie)
{
	siginfo_t *info, *t;

	info = (siginfo_t *) sie->siginfo.data;
	t = rst_mem_alloc(sizeof(siginfo_t), RM_PRIVATE);
	if (!t)
		return -1;

	memcpy(t, info, sizeof(*info));

	return 0;
}

static int open_signal_image(int type, pid_t pid, unsigned int *nr)
{
	int ret;
	struct cr_img *img;

	img = open_image(type, O_RSTR, pid);
	if (!img)
		return -1;

	*nr = 0;
	while (1) {
		SiginfoEntry *sie;

		ret = pb_read_one_eof(img, &sie, PB_SIGINFO);
		if (ret <= 0)
			break;
		if (sie->siginfo.len != sizeof(siginfo_t)) {
			pr_err("Unknown image format\n");
			ret = -1;
			break;
		}

		ret = signal_to_mem(sie);
		if (ret)
			break;

		(*nr)++;

		siginfo_entry__free_unpacked(sie, NULL);
	}

	close_image(img);

	return ret ? : 0;
}

static int prepare_one_signal_queue(SignalQueueEntry *sqe, unsigned int *nr)
{
	int i;

	for (i = 0; i < sqe->n_signals; i++)
		if (signal_to_mem(sqe->signals[i]))
			return -1;

	*nr = sqe->n_signals;

	return 0;
}

static unsigned int *siginfo_priv_nr; /* FIXME -- put directly on thread_args */

static int prepare_signals(int pid, struct task_restore_args *ta, CoreEntry *leader_core)
{
	int ret = -1, i;

	ta->siginfo = (siginfo_t *)rst_mem_align_cpos(RM_PRIVATE);
	siginfo_priv_nr = xmalloc(sizeof(int) * current->nr_threads);
	if (siginfo_priv_nr == NULL)
		goto out;

	/* Prepare shared signals */
	if (!leader_core->tc->signals_s)/*backward compatibility*/
		ret = open_signal_image(CR_FD_SIGNAL, pid, &ta->siginfo_n);
	else
		ret = prepare_one_signal_queue(leader_core->tc->signals_s, &ta->siginfo_n);

	if (ret < 0)
		goto out;

	for (i = 0; i < current->nr_threads; i++) {
		if (!current->core[i]->thread_core->signals_p)/*backward compatibility*/
			ret = open_signal_image(CR_FD_PSIGNAL,
					current->threads[i].ns[0].virt, &siginfo_priv_nr[i]);
		else
			ret = prepare_one_signal_queue(current->core[i]->thread_core->signals_p,
										&siginfo_priv_nr[i]);
		if (ret < 0)
			goto out;
	}
out:
	return ret;
}

extern void __gcov_flush(void) __attribute__((weak));
void __gcov_flush(void) {}

static void rst_reloc_creds(struct thread_restore_args *thread_args,
			    unsigned long *creds_pos_next)
{
	struct thread_creds_args *args;

	if (unlikely(!*creds_pos_next))
		return;

	args = rst_mem_remap_ptr(*creds_pos_next, RM_PRIVATE);

	if (args->lsm_profile)
		args->lsm_profile = rst_mem_remap_ptr(args->mem_lsm_profile_pos, RM_PRIVATE);
	if (args->groups)
		args->groups = rst_mem_remap_ptr(args->mem_groups_pos, RM_PRIVATE);

	*creds_pos_next = args->mem_pos_next;
	thread_args->creds_args = args;
}

static struct thread_creds_args *
rst_prep_creds_args(CredsEntry *ce, unsigned long *prev_pos)
{
	unsigned long this_pos;
	struct thread_creds_args *args;

	if (!verify_cap_size(ce)) {
		pr_err("Caps size mismatch %d %d %d %d\n",
		       (int)ce->n_cap_inh, (int)ce->n_cap_eff,
		       (int)ce->n_cap_prm, (int)ce->n_cap_bnd);
		return ERR_PTR(-EINVAL);
	}

	this_pos = rst_mem_align_cpos(RM_PRIVATE);

	args = rst_mem_alloc(sizeof(*args), RM_PRIVATE);
	if (!args)
		return ERR_PTR(-ENOMEM);

	args->cap_last_cap = kdat.last_cap;
	memcpy(&args->creds, ce, sizeof(args->creds));

	if (ce->lsm_profile || opts.lsm_supplied) {
		char *rendered = NULL, *profile;

		profile = ce->lsm_profile;
		if (opts.lsm_supplied)
			profile = opts.lsm_profile;

		if (validate_lsm(profile) < 0)
			return ERR_PTR(-EINVAL);

		if (profile && render_lsm_profile(profile, &rendered)) {
			return ERR_PTR(-EINVAL);
		}

		if (rendered) {
			size_t lsm_profile_len;
			char *lsm_profile;

			args->mem_lsm_profile_pos = rst_mem_align_cpos(RM_PRIVATE);
			lsm_profile_len = strlen(rendered);
			lsm_profile = rst_mem_alloc(lsm_profile_len + 1, RM_PRIVATE);
			if (!lsm_profile) {
				xfree(rendered);
				return ERR_PTR(-ENOMEM);
			}

			args = rst_mem_remap_ptr(this_pos, RM_PRIVATE);
			args->lsm_profile = lsm_profile;
			strncpy(args->lsm_profile, rendered, lsm_profile_len);
			xfree(rendered);
		}
	} else {
		args->lsm_profile = NULL;
		args->mem_lsm_profile_pos = 0;
	}

	/*
	 * Zap fields which we can't use.
	 */
	args->creds.cap_inh = NULL;
	args->creds.cap_eff = NULL;
	args->creds.cap_prm = NULL;
	args->creds.cap_bnd = NULL;
	args->creds.groups = NULL;
	args->creds.lsm_profile = NULL;

	memcpy(args->cap_inh, ce->cap_inh, sizeof(args->cap_inh));
	memcpy(args->cap_eff, ce->cap_eff, sizeof(args->cap_eff));
	memcpy(args->cap_prm, ce->cap_prm, sizeof(args->cap_prm));
	memcpy(args->cap_bnd, ce->cap_bnd, sizeof(args->cap_bnd));

	if (ce->n_groups) {
		unsigned int *groups;

		args->mem_groups_pos = rst_mem_align_cpos(RM_PRIVATE);
		groups = rst_mem_alloc(ce->n_groups * sizeof(u32), RM_PRIVATE);
		if (!groups)
			return ERR_PTR(-ENOMEM);
		args = rst_mem_remap_ptr(this_pos, RM_PRIVATE);
		args->groups = groups;
		memcpy(args->groups, ce->groups, ce->n_groups * sizeof(u32));
	} else {
		args->groups = NULL;
		args->mem_groups_pos = 0;
	}

	args->mem_pos_next = 0;

	if (prev_pos) {
		if (*prev_pos) {
			struct thread_creds_args *prev;

			prev = rst_mem_remap_ptr(*prev_pos, RM_PRIVATE);
			prev->mem_pos_next = this_pos;
		}
		*prev_pos = this_pos;
	}
	return args;
}

static int rst_prep_creds_from_img(pid_t pid)
{
	CredsEntry *ce = NULL;
	struct cr_img *img;
	int ret;

	img = open_image(CR_FD_CREDS, O_RSTR, pid);
	if (!img)
		return -ENOENT;

	ret = pb_read_one(img, &ce, PB_CREDS);
	close_image(img);

	if (ret > 0) {
		struct thread_creds_args *args;

		args = rst_prep_creds_args(ce, NULL);
		if (IS_ERR(args))
			ret = PTR_ERR(args);
		else
			ret = 0;
	}
	creds_entry__free_unpacked(ce, NULL);
	return ret;
}

static int rst_prep_creds(pid_t pid, CoreEntry *core, unsigned long *creds_pos)
{
	struct thread_creds_args *args = NULL;
	unsigned long this_pos = 0;
	size_t i;

	/*
	 * This is _really_ very old image
	 * format where @thread_core were not
	 * present. It means we don't have
	 * creds either, just ignore and exit
	 * early.
	 */
	if (unlikely(!core->thread_core)) {
		*creds_pos = 0;
		return 0;
	}

	*creds_pos = rst_mem_align_cpos(RM_PRIVATE);

	/*
	 * Old format: one Creds per task carried in own image file.
	 */
	if (!core->thread_core->creds)
		return rst_prep_creds_from_img(pid);

	for (i = 0; i < current->nr_threads; i++) {
		CredsEntry *ce = current->core[i]->thread_core->creds;

		args = rst_prep_creds_args(ce, &this_pos);
		if (IS_ERR(args))
			return PTR_ERR(args);
	}

	return 0;
}

static void *restorer_munmap_addr(CoreEntry *core, void *restorer_blob)
{
#ifdef CONFIG_COMPAT
	if (core_is_compat(core))
		return restorer_sym(restorer_blob, arch_export_unmap_compat);
#endif
	return restorer_sym(restorer_blob, arch_export_unmap);
}

static int sigreturn_restore(pid_t pid, struct task_restore_args *task_args, unsigned long alen, CoreEntry *core)
{
	void *mem = MAP_FAILED;
	void *restore_task_exec_start;

	long new_sp;
	long ret;

	long rst_mem_size;
	long memzone_size;

	struct thread_restore_args *thread_args;
	struct restore_mem_zone *mz;

#ifdef CONFIG_VDSO
	struct vdso_maps vdso_maps_rt;
	unsigned long vdso_rt_size = 0;
#endif

	struct vm_area_list self_vmas;
	struct vm_area_list *vmas = &rsti(current)->vmas;
	int i, siginfo_n;

	unsigned long creds_pos = 0;
	unsigned long creds_pos_next;

	sigset_t blockmask;

	pr_info("Restore via sigreturn\n");

	/* pr_info_vma_list(&self_vma_list); */

	BUILD_BUG_ON(sizeof(struct task_restore_args) & 1);
	BUILD_BUG_ON(sizeof(struct thread_restore_args) & 1);

	/*
	 * Read creds info for every thread and allocate memory
	 * needed so we can use this data inside restorer.
	 */
	if (rst_prep_creds(pid, core, &creds_pos))
		goto err_nv;

	/*
	 * We're about to search for free VM area and inject the restorer blob
	 * into it. No irrelevant mmaps/mremaps beyond this point, otherwise
	 * this unwanted mapping might get overlapped by the restorer.
	 */

	ret = parse_self_maps_lite(&self_vmas);
	if (ret < 0)
		goto err;

	rst_mem_size = rst_mem_lock();
	memzone_size = round_up(sizeof(struct restore_mem_zone) * current->nr_threads, page_size());
	task_args->bootstrap_len = restorer_len + memzone_size + alen + rst_mem_size;
	BUG_ON(task_args->bootstrap_len & (PAGE_SIZE - 1));
	pr_info("%d threads require %ldK of memory\n",
			current->nr_threads, KBYTES(task_args->bootstrap_len));

#ifdef CONFIG_VDSO
	if (core_is_compat(core))
		vdso_maps_rt = vdso_maps_compat;
	else
		vdso_maps_rt = vdso_maps;
	/*
	 * Figure out how much memory runtime vdso and vvar will need.
	 */
	vdso_rt_size = vdso_maps_rt.sym.vdso_size;
	if (vdso_rt_size && vdso_maps_rt.sym.vvar_size)
		vdso_rt_size += ALIGN(vdso_maps_rt.sym.vvar_size, PAGE_SIZE);
	task_args->bootstrap_len += vdso_rt_size;
#endif

	/*
	 * Restorer is a blob (code + args) that will get mapped in some
	 * place, that should _not_ intersect with both -- current mappings
	 * and mappings of the task we're restoring here. The subsequent
	 * call finds the start address for the restorer.
	 *
	 * After the start address is found we populate it with the restorer
	 * parts one by one (some are remap-ed, some are mmap-ed and copied
	 * or inited from scratch).
	 */

	mem = (void *)restorer_get_vma_hint(&vmas->h, &self_vmas.h,
					      task_args->bootstrap_len);
	if (mem == (void *)-1) {
		pr_err("No suitable area for task_restore bootstrap (%ldK)\n",
				task_args->bootstrap_len);
		goto err;
	}

	pr_info("Found bootstrap VMA hint at: %p (needs ~%ldK)\n",
			mem, KBYTES(task_args->bootstrap_len));

	ret = remap_restorer_blob(mem);
	if (ret < 0)
		goto err;

	/*
	 * Prepare a memory map for restorer. Note a thread space
	 * might be completely unused so it's here just for convenience.
	 */
	task_args->clone_restore_fn	= restorer_sym(mem, arch_export_restore_thread);
	restore_task_exec_start		= restorer_sym(mem, arch_export_restore_task);
	rsti(current)->munmap_restorer	= restorer_munmap_addr(core, mem);

	task_args->bootstrap_start = mem;
	mem += restorer_len;

	/* VMA we need for stacks and sigframes for threads */
	if (mmap(mem, memzone_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0) != mem) {
		pr_err("Can't mmap section for restore code\n");
		goto err;
	}

	memzero(mem, memzone_size);
	mz = mem;
	mem += memzone_size;

	/* New home for task_restore_args and thread_restore_args */
	task_args = mremap(task_args, alen, alen, MREMAP_MAYMOVE|MREMAP_FIXED, mem);
	if (task_args != mem) {
		pr_perror("Can't move task args");
		goto err;
	}

	task_args->rst_mem = mem;
	task_args->rst_mem_size = rst_mem_size + alen;
	thread_args = (struct thread_restore_args *)(task_args + 1);

	/*
	 * And finally -- the rest arguments referenced by task_ and
	 * thread_restore_args. Pointers will get remapped below.
	 */
	mem += alen;
	if (rst_mem_remap(mem))
		goto err;

	/*
	 * At this point we've found a gap in VM that fits in both -- current
	 * and target tasks' mappings -- and its structure is
	 *
	 * | restorer code | memzone (stacks and sigframes) | arguments |
	 *
	 * Arguments is task_restore_args, thread_restore_args-s and all
	 * the bunch of objects allocated with rst_mem_alloc().
	 * Note, that the task_args itself is inside the 3rd section and (!)
	 * it gets unmapped at the very end of __export_restore_task
	 */

	task_args->proc_fd = dup(get_service_fd(PROC_FD_OFF));
	if (task_args->proc_fd < 0) {
		pr_perror("can't dup proc fd");
		goto err;
	}

	task_args->breakpoint = &rsti(current)->breakpoint;
	task_args->fault_strategy = fi_strategy;

	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &blockmask, NULL) == -1) {
		pr_perror("Can not set mask of blocked signals");
		return -1;
	}

	task_args->task_entries = rst_mem_remap_ptr(task_entries_pos, RM_SHREMAP);

	task_args->premmapped_addr = (unsigned long)rsti(current)->premmapped_addr;
	task_args->premmapped_len = rsti(current)->premmapped_len;

	task_args->task_size = kdat.task_size;

	RST_MEM_FIXUP_PPTR(task_args->vmas);
	RST_MEM_FIXUP_PPTR(task_args->rings);
	RST_MEM_FIXUP_PPTR(task_args->tcp_socks);
	RST_MEM_FIXUP_PPTR(task_args->timerfd);
	RST_MEM_FIXUP_PPTR(task_args->posix_timers);
	RST_MEM_FIXUP_PPTR(task_args->siginfo);
	RST_MEM_FIXUP_PPTR(task_args->rlims);
	RST_MEM_FIXUP_PPTR(task_args->helpers);
	RST_MEM_FIXUP_PPTR(task_args->zombies);
	RST_MEM_FIXUP_PPTR(task_args->seccomp_filters);
	RST_MEM_FIXUP_PPTR(task_args->vma_ios);

	if (core->tc->has_seccomp_mode)
		task_args->seccomp_mode = core->tc->seccomp_mode;

	task_args->compatible_mode = core_is_compat(core);
	/*
	 * Arguments for task restoration.
	 */

	BUG_ON(core->mtype != CORE_ENTRY__MARCH);

	task_args->logfd	= log_get_fd();
	task_args->loglevel	= log_get_loglevel();
	log_get_logstart(&task_args->logstart);
	task_args->sigchld_act	= sigchld_act;

	strncpy(task_args->comm, core->tc->comm, sizeof(task_args->comm));

	/*
	 * Fill up per-thread data.
	 */
	creds_pos_next = creds_pos;
	siginfo_n = task_args->siginfo_n;
	for (i = 0; i < current->nr_threads; i++) {
		CoreEntry *tcore;
		struct rt_sigframe *sigframe;
		k_rtsigset_t *blkset = NULL;

		thread_args[i].pid = current->threads[i].ns[0].virt;
		thread_args[i].siginfo_n = siginfo_priv_nr[i];
		thread_args[i].siginfo = task_args->siginfo;
		thread_args[i].siginfo += siginfo_n;
		siginfo_n += thread_args[i].siginfo_n;

		/* skip self */
		if (thread_args[i].pid == pid) {
			task_args->t = thread_args + i;
			tcore = core;
			blkset = (void *)&tcore->tc->blk_sigset;
		} else {
			tcore = current->core[i];
			if (tcore->thread_core->has_blk_sigset)
				blkset = (void *)&tcore->thread_core->blk_sigset;
		}

		if ((tcore->tc || tcore->ids) && thread_args[i].pid != pid) {
			pr_err("Thread has optional fields present %d\n",
			       thread_args[i].pid);
			ret = -1;
		}

		if (ret < 0) {
			pr_err("Can't read core data for thread %d\n",
			       thread_args[i].pid);
			goto err;
		}

		thread_args[i].ta		= task_args;
		thread_args[i].gpregs		= *CORE_THREAD_ARCH_INFO(tcore)->gpregs;
		thread_args[i].clear_tid_addr	= CORE_THREAD_ARCH_INFO(tcore)->clear_tid_addr;
		core_get_tls(tcore, &thread_args[i].tls);

		rst_reloc_creds(&thread_args[i], &creds_pos_next);

		thread_args[i].futex_rla	= tcore->thread_core->futex_rla;
		thread_args[i].futex_rla_len	= tcore->thread_core->futex_rla_len;
		thread_args[i].pdeath_sig	= tcore->thread_core->pdeath_sig;
		if (tcore->thread_core->pdeath_sig > _KNSIG) {
			pr_err("Pdeath signal is too big\n");
			goto err;
		}

		ret = prep_sched_info(&thread_args[i].sp, tcore->thread_core);
		if (ret)
			goto err;

		thread_args[i].mz = mz + i;
		sigframe = (struct rt_sigframe *)&mz[i].rt_sigframe;

		if (construct_sigframe(sigframe, sigframe, blkset, tcore))
			goto err;

		if (thread_args[i].pid != pid)
			core_entry__free_unpacked(tcore, NULL);

		pr_info("Thread %4d stack %8p rt_sigframe %8p\n",
				i, mz[i].stack, mz[i].rt_sigframe);

	}

#ifdef CONFIG_VDSO
	/*
	 * Restorer needs own copy of vdso parameters. Runtime
	 * vdso must be kept non intersecting with anything else,
	 * since we need it being accessible even when own
	 * self-vmas are unmaped.
	 */
	mem += rst_mem_size;
	task_args->vdso_rt_parked_at = (unsigned long)mem;
	task_args->vdso_maps_rt = vdso_maps_rt;
	task_args->vdso_rt_size = vdso_rt_size;
	task_args->can_map_vdso = kdat.can_map_vdso;
#endif

	new_sp = restorer_stack(task_args->t->mz);

	/* No longer need it */
	core_entry__free_unpacked(core, NULL);
	xfree(current->core);

	/*
	 * Now prepare run-time data for threads restore.
	 */
	task_args->nr_threads		= current->nr_threads;
	task_args->thread_args		= thread_args;

	/*
	 * Make root and cwd restore _that_ late not to break any
	 * attempts to open files by paths above (e.g. /proc).
	 */

	if (restore_fs(current))
		goto err;

	close_image_dir();
	close_proc();
	close_service_fd(ROOT_FD_OFF);
	close_service_fd(USERNSD_SK);
	close_service_fd(FDSTORE_SK_OFF);
	close_service_fd(RPC_SK_OFF);

	__gcov_flush();

	pr_info("task_args: %p\n"
		"task_args->pid: %d\n"
		"task_args->nr_threads: %d\n"
		"task_args->clone_restore_fn: %p\n"
		"task_args->thread_args: %p\n",
		task_args, task_args->t->pid,
		task_args->nr_threads,
		task_args->clone_restore_fn,
		task_args->thread_args);

	/*
	 * An indirect call to task_restore, note it never returns
	 * and restoring core is extremely destructive.
	 */

	JUMP_TO_RESTORER_BLOB(new_sp, restore_task_exec_start, task_args);

err:
	free_mappings(&self_vmas);
err_nv:
	/* Just to be sure */
	exit(1);
	return -1;
}
