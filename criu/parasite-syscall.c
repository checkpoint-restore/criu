#include <unistd.h>
#include <inttypes.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "common/config.h"
#include "common/compiler.h"
#include "types.h"
#include "protobuf.h"
#include "images/sa.pb-c.h"
#include "images/timer.pb-c.h"
#include "images/creds.pb-c.h"
#include "images/core.pb-c.h"
#include "images/pagemap.pb-c.h"

#include "imgset.h"
#include "parasite-syscall.h"
#include "parasite.h"
#include "crtools.h"
#include "namespaces.h"
#include "kerndat.h"
#include "pstree.h"
#include "posix-timer.h"
#include "mem.h"
#include "criu-log.h"
#include "vma.h"
#include "proc_parse.h"
#include "aio.h"
#include "fault-injection.h"
#include <compel/plugins/std/syscall-codes.h>
#include "signal.h"
#include "sigframe.h"

#include <string.h>
#include <stdlib.h>
#include <elf.h>

#include "dump.h"
#include "restorer.h"

#include "infect.h"
#include "infect-rpc.h"
#include "pie/parasite-blob.h"

unsigned long get_exec_start(struct vm_area_list *vmas)
{
	struct vma_area *vma_area;

	list_for_each_entry(vma_area, &vmas->h, list) {
		unsigned long len;

		if (vma_area->e->start >= kdat.task_size)
			continue;
		if (!(vma_area->e->prot & PROT_EXEC))
			continue;

		len = vma_area_len(vma_area);
		if (len < PARASITE_START_AREA_MIN) {
			pr_warn("Suspiciously short VMA @%#lx\n", (unsigned long)vma_area->e->start);
			continue;
		}

		return vma_area->e->start;
	}

	return 0;
}

/*
 * We need to detect parasite crashes not to hang on socket operations.
 * Since CRIU holds parasite with ptrace, it will receive SIGCHLD if the
 * latter would crash.
 *
 * This puts a restriction on how to execute a sub-process on dump stage.
 * One should use the cr_system helper, that blocks sigcild and waits
 * for the spawned program to finish.
 */
static void sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	int pid, status;

	pid = waitpid(-1, &status, WNOHANG);
	if (pid <= 0)
		return;

	pr_err("si_code=%d si_pid=%d si_status=%d\n", siginfo->si_code, siginfo->si_pid, siginfo->si_status);

	if (WIFEXITED(status))
		pr_err("%d exited with %d unexpectedly\n", pid, WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		pr_err("%d was killed by %d unexpectedly: %s\n", pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
	else if (WIFSTOPPED(status))
		pr_err("%d was stopped by %d unexpectedly\n", pid, WSTOPSIG(status));

	exit(1);
}

static int alloc_groups_copy_creds(CredsEntry *ce, struct parasite_dump_creds *c)
{
	BUILD_BUG_ON(sizeof(ce->groups[0]) != sizeof(c->groups[0]));
	BUILD_BUG_ON(sizeof(ce->cap_inh[0]) != sizeof(c->cap_inh[0]));
	BUILD_BUG_ON(sizeof(ce->cap_prm[0]) != sizeof(c->cap_prm[0]));
	BUILD_BUG_ON(sizeof(ce->cap_eff[0]) != sizeof(c->cap_eff[0]));
	BUILD_BUG_ON(sizeof(ce->cap_bnd[0]) != sizeof(c->cap_bnd[0]));

	BUG_ON(ce->n_cap_inh != CR_CAP_SIZE);
	BUG_ON(ce->n_cap_prm != CR_CAP_SIZE);
	BUG_ON(ce->n_cap_eff != CR_CAP_SIZE);
	BUG_ON(ce->n_cap_bnd != CR_CAP_SIZE);

	memcpy(ce->cap_inh, c->cap_inh, sizeof(c->cap_inh[0]) * CR_CAP_SIZE);
	memcpy(ce->cap_prm, c->cap_prm, sizeof(c->cap_prm[0]) * CR_CAP_SIZE);
	memcpy(ce->cap_eff, c->cap_eff, sizeof(c->cap_eff[0]) * CR_CAP_SIZE);
	memcpy(ce->cap_bnd, c->cap_bnd, sizeof(c->cap_bnd[0]) * CR_CAP_SIZE);

	ce->secbits = c->secbits;
	ce->n_groups = c->ngroups;

	ce->groups = xmemdup(c->groups, sizeof(c->groups[0]) * c->ngroups);

	ce->uid = c->uids[0];
	ce->gid = c->gids[0];
	ce->euid = c->uids[1];
	ce->egid = c->gids[1];
	ce->suid = c->uids[2];
	ce->sgid = c->gids[2];
	ce->fsuid = c->uids[3];
	ce->fsgid = c->gids[3];

	return ce->groups ? 0 : -ENOMEM;
}

int parasite_dump_thread_leader_seized(struct parasite_ctl *ctl, int pid, CoreEntry *core)
{
	ThreadCoreEntry *tc = core->thread_core;
	struct parasite_dump_thread *args;
	struct parasite_dump_creds *pc;
	int ret;

	args = compel_parasite_args(ctl, struct parasite_dump_thread);

	pc = args->creds;
	pc->cap_last_cap = kdat.last_cap;

	ret = compel_rpc_call_sync(PARASITE_CMD_DUMP_THREAD, ctl);
	if (ret < 0)
		return ret;

	ret = alloc_groups_copy_creds(tc->creds, pc);
	if (ret) {
		pr_err("Can't copy creds for thread leader %d\n", pid);
		return -1;
	}

	compel_arch_get_tls_task(ctl, &args->tls);

	return dump_thread_core(pid, core, args);
}

int parasite_dump_thread_seized(struct parasite_thread_ctl *tctl, struct parasite_ctl *ctl, int id, struct pid *tid,
				CoreEntry *core)
{
	struct parasite_dump_thread *args;
	pid_t pid = tid->real;
	ThreadCoreEntry *tc = core->thread_core;
	CredsEntry *creds = tc->creds;
	struct parasite_dump_creds *pc;
	int ret;

	BUG_ON(id == 0); /* Leader is dumped in dump_task_core_all */

	args = compel_parasite_args(ctl, struct parasite_dump_thread);

	pc = args->creds;
	pc->cap_last_cap = kdat.last_cap;

	tc->has_blk_sigset = true;
#ifdef CONFIG_MIPS
	memcpy(&tc->blk_sigset, (unsigned long *)compel_thread_sigmask(tctl), sizeof(tc->blk_sigset));
	memcpy(&tc->blk_sigset_extended, (unsigned long *)compel_thread_sigmask(tctl) + 1, sizeof(tc->blk_sigset));
#else
	memcpy(&tc->blk_sigset, compel_thread_sigmask(tctl), sizeof(k_rtsigset_t));
#endif
	ret = compel_get_thread_regs(tctl, save_task_regs, core);
	if (ret) {
		pr_err("Can't obtain regs for thread %d\n", pid);
		goto err_rth;
	}

	ret = compel_arch_fetch_thread_area(tctl);
	if (ret) {
		pr_err("Can't obtain thread area of %d\n", pid);
		goto err_rth;
	}

	compel_arch_get_tls_thread(tctl, &args->tls);

	ret = compel_run_in_thread(tctl, PARASITE_CMD_DUMP_THREAD);
	if (ret) {
		pr_err("Can't init thread in parasite %d\n", pid);
		goto err_rth;
	}

	ret = alloc_groups_copy_creds(creds, pc);
	if (ret) {
		pr_err("Can't copy creds for thread %d\n", pid);
		goto err_rth;
	}

	compel_release_thread(tctl);

	tid->ns[0].virt = args->tid;
	return dump_thread_core(pid, core, args);

err_rth:
	compel_release_thread(tctl);
	return -1;
}

int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct pstree_item *item)
{
	TaskCoreEntry *tc = item->core[0]->tc;
	struct parasite_dump_sa_args *args;
	int ret, sig;
	SaEntry *sa, **psa;

	args = compel_parasite_args(ctl, struct parasite_dump_sa_args);

	ret = compel_rpc_call_sync(PARASITE_CMD_DUMP_SIGACTS, ctl);
	if (ret < 0)
		return ret;

	psa = xmalloc((SIGMAX - 2) * (sizeof(SaEntry *) + sizeof(SaEntry)));
	if (!psa)
		return -1;

	sa = (SaEntry *)(psa + SIGMAX - 2);

	tc->n_sigactions = SIGMAX - 2;
	tc->sigactions = psa;

	for (sig = 1; sig <= SIGMAX; sig++) {
		int i = sig - 1;

		if (sig == SIGSTOP || sig == SIGKILL)
			continue;

		sa_entry__init(sa);
		ASSIGN_TYPED(sa->sigaction, encode_pointer(args->sas[i].rt_sa_handler));
		ASSIGN_TYPED(sa->flags, args->sas[i].rt_sa_flags);
		ASSIGN_TYPED(sa->restorer, encode_pointer(args->sas[i].rt_sa_restorer));
#ifdef CONFIG_MIPS
		sa->has_mask_extended = 1;
		BUILD_BUG_ON(sizeof(sa->mask) * 2 != sizeof(args->sas[0].rt_sa_mask.sig));
		memcpy(&sa->mask, &(args->sas[i].rt_sa_mask.sig[0]), sizeof(sa->mask));
		memcpy(&sa->mask_extended, &(args->sas[i].rt_sa_mask.sig[1]), sizeof(sa->mask));
#else
		BUILD_BUG_ON(sizeof(sa->mask) != sizeof(args->sas[0].rt_sa_mask.sig));
		memcpy(&sa->mask, args->sas[i].rt_sa_mask.sig, sizeof(sa->mask));
#endif
		sa->has_compat_sigaction = true;
		sa->compat_sigaction = !compel_mode_native(ctl);

		*(psa++) = sa++;
	}

	return 0;
}

static void encode_itimer(struct itimerval *v, ItimerEntry *ie)
{
	ie->isec = v->it_interval.tv_sec;
	ie->iusec = v->it_interval.tv_usec;
	ie->vsec = v->it_value.tv_sec;
	ie->vusec = v->it_value.tv_usec;
}

int parasite_dump_itimers_seized(struct parasite_ctl *ctl, struct pstree_item *item)
{
	CoreEntry *core = item->core[0];
	struct parasite_dump_itimers_args *args;
	int ret;

	args = compel_parasite_args(ctl, struct parasite_dump_itimers_args);

	ret = compel_rpc_call_sync(PARASITE_CMD_DUMP_ITIMERS, ctl);
	if (ret < 0)
		return ret;

	encode_itimer((&args->real), (core->tc->timers->real));
	encode_itimer((&args->virt), (core->tc->timers->virt));
	encode_itimer((&args->prof), (core->tc->timers->prof));

	return 0;
}

static int core_alloc_posix_timers(TaskTimersEntry *tte, int n, PosixTimerEntry **pte)
{
	int sz;

	/*
	 * Will be free()-ed in core_entry_free()
	 */

	sz = n * (sizeof(PosixTimerEntry *) + sizeof(PosixTimerEntry));
	tte->posix = xmalloc(sz);
	if (!tte->posix)
		return -1;

	tte->n_posix = n;
	*pte = (PosixTimerEntry *)(tte->posix + n);
	return 0;
}

static int encode_notify_thread_id(pid_t rtid, struct pstree_item *item, PosixTimerEntry *pte)
{
	pid_t vtid = 0;
	int i;

	if (rtid == 0)
		return 0;

	if (!(root_ns_mask & CLONE_NEWPID)) {
		/* Non-pid-namespace case */
		pte->notify_thread_id = rtid;
		pte->has_notify_thread_id = true;
		return 0;
	}

	/* Pid-namespace case */
	if (!kdat.has_nspid) {
		pr_err("Have no NSpid support to dump notify thread id in pid namespace\n");
		return -1;
	}

	for (i = 0; i < item->nr_threads; i++) {
		if (item->threads[i].real != rtid)
			continue;

		vtid = item->threads[i].ns[0].virt;
		break;
	}

	if (vtid == 0) {
		pr_err("Unable to convert the notify thread id %d\n", rtid);
		return -1;
	}

	pte->notify_thread_id = vtid;
	pte->has_notify_thread_id = true;
	return 0;
}

static int encode_posix_timer(struct pstree_item *item, struct posix_timer *v, struct proc_posix_timer *vp,
			      PosixTimerEntry *pte)
{
	pte->it_id = vp->spt.it_id;
	pte->clock_id = vp->spt.clock_id;
	pte->si_signo = vp->spt.si_signo;
	pte->it_sigev_notify = vp->spt.it_sigev_notify;
	pte->sival_ptr = encode_pointer(vp->spt.sival_ptr);

	pte->overrun = v->overrun;

	pte->isec = v->val.it_interval.tv_sec;
	pte->insec = v->val.it_interval.tv_nsec;
	pte->vsec = v->val.it_value.tv_sec;
	pte->vnsec = v->val.it_value.tv_nsec;

	if (encode_notify_thread_id(vp->spt.notify_thread_id, item, pte))
		return -1;

	return 0;
}

int parasite_dump_posix_timers_seized(struct proc_posix_timers_stat *proc_args, struct parasite_ctl *ctl,
				      struct pstree_item *item)
{
	CoreEntry *core = item->core[0];
	TaskTimersEntry *tte = core->tc->timers;
	PosixTimerEntry *pte;
	struct proc_posix_timer *temp;
	struct parasite_dump_posix_timers_args *args;
	int ret, exit_code = -1;
	int args_size;
	int i;

	if (core_alloc_posix_timers(tte, proc_args->timer_n, &pte))
		return -1;

	args_size = posix_timers_dump_size(proc_args->timer_n);
	args = compel_parasite_args_s(ctl, args_size);
	args->timer_n = proc_args->timer_n;

	i = 0;
	list_for_each_entry(temp, &proc_args->timers, list) {
		args->timer[i].it_id = temp->spt.it_id;
		i++;
	}

	ret = compel_rpc_call_sync(PARASITE_CMD_DUMP_POSIX_TIMERS, ctl);
	if (ret < 0)
		goto end_posix;

	i = 0;
	list_for_each_entry(temp, &proc_args->timers, list) {
		posix_timer_entry__init(&pte[i]);
		if (encode_posix_timer(item, &args->timer[i], temp, &pte[i]))
			goto end_posix;
		tte->posix[i] = &pte[i];
		i++;
	}

	exit_code = 0;
end_posix:
	free_posix_timers(proc_args);
	return exit_code;
}

int parasite_dump_misc_seized(struct parasite_ctl *ctl, struct parasite_dump_misc *misc)
{
	struct parasite_dump_misc *ma;

	ma = compel_parasite_args(ctl, struct parasite_dump_misc);
	if (compel_rpc_call_sync(PARASITE_CMD_DUMP_MISC, ctl) < 0)
		return -1;

	*misc = *ma;
	return 0;
}

struct parasite_tty_args *parasite_dump_tty(struct parasite_ctl *ctl, int fd, int type)
{
	struct parasite_tty_args *p;

	p = compel_parasite_args(ctl, struct parasite_tty_args);
	p->fd = fd;
	p->type = type;

	if (compel_rpc_call_sync(PARASITE_CMD_DUMP_TTY, ctl) < 0)
		return NULL;

	return p;
}

int parasite_drain_fds_seized(struct parasite_ctl *ctl, struct parasite_drain_fd *dfds, int nr_fds, int off, int *lfds,
			      struct fd_opts *opts)
{
	int ret = -1, size, sk;
	struct parasite_drain_fd *args;

	size = drain_fds_size(dfds);
	args = compel_parasite_args_s(ctl, size);
	args->nr_fds = nr_fds;
	memcpy(&args->fds, dfds->fds + off, sizeof(int) * nr_fds);

	ret = compel_rpc_call(PARASITE_CMD_DRAIN_FDS, ctl);
	if (ret) {
		pr_err("Parasite failed to drain descriptors\n");
		goto err;
	}

	sk = compel_rpc_sock(ctl);
	ret = recv_fds(sk, lfds, nr_fds, opts, sizeof(struct fd_opts));
	if (ret)
		pr_err("Can't retrieve FDs from socket\n");

	ret |= compel_rpc_sync(PARASITE_CMD_DRAIN_FDS, ctl);
err:
	return ret;
}

int parasite_get_proc_fd_seized(struct parasite_ctl *ctl)
{
	int ret = -1, fd, sk;

	ret = compel_rpc_call(PARASITE_CMD_GET_PROC_FD, ctl);
	if (ret) {
		pr_err("Parasite failed to get proc fd\n");
		return ret;
	}

	sk = compel_rpc_sock(ctl);
	fd = recv_fd(sk);
	if (fd < 0)
		pr_err("Can't retrieve FD from socket\n");
	if (compel_rpc_sync(PARASITE_CMD_GET_PROC_FD, ctl)) {
		close_safe(&fd);
		return -1;
	}

	return fd;
}

/* This is officially the 50000'th line in the CRIU source code */

int parasite_dump_cgroup(struct parasite_ctl *ctl, struct parasite_dump_cgroup_args *cgroup)
{
	int ret;
	struct parasite_dump_cgroup_args *ca;

	ca = compel_parasite_args(ctl, struct parasite_dump_cgroup_args);
	ret = compel_rpc_call_sync(PARASITE_CMD_DUMP_CGROUP, ctl);
	if (ret) {
		pr_err("Parasite failed to dump /proc/self/cgroup\n");
		return ret;
	}

	*cgroup = *ca;
	return 0;
}

static unsigned long parasite_args_size = PARASITE_ARG_SIZE_MIN;
void parasite_ensure_args_size(unsigned long sz)
{
	if (parasite_args_size < sz)
		parasite_args_size = sz;
}

static int make_sigframe(void *arg, struct rt_sigframe *sf, struct rt_sigframe *rtsf, k_rtsigset_t *bs)
{
	return construct_sigframe(sf, rtsf, bs, (CoreEntry *)arg);
}

static int parasite_prepare_threads(struct parasite_ctl *ctl, struct pstree_item *item)
{
	struct parasite_thread_ctl **thread_ctls;
	uint64_t *thread_sp;
	int i;

	thread_ctls = xzalloc(sizeof(*thread_ctls) * item->nr_threads);
	if (!thread_ctls)
		return -1;

	thread_sp = xzalloc(sizeof(*thread_sp) * item->nr_threads);
	if (!thread_sp)
		goto free_ctls;

	for (i = 0; i < item->nr_threads; i++) {
		struct pid *tid = &item->threads[i];

		if (item->pid->real == tid->real) {
			thread_sp[i] = compel_get_leader_sp(ctl);
			continue;
		}

		thread_ctls[i] = compel_prepare_thread(ctl, tid->real);
		if (!thread_ctls[i])
			goto free_sp;

		thread_sp[i] = compel_get_thread_sp(thread_ctls[i]);
	}

	dmpi(item)->thread_ctls = thread_ctls;
	dmpi(item)->thread_sp = thread_sp;

	return 0;

free_sp:
	xfree(thread_sp);
free_ctls:
	xfree(thread_ctls);
	return -1;
}

struct parasite_ctl *parasite_infect_seized(pid_t pid, struct pstree_item *item, struct vm_area_list *vma_area_list)
{
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	unsigned long p;
	int ret;

	BUG_ON(item->threads[0].real != pid);

	p = get_exec_start(vma_area_list);
	if (!p) {
		pr_err("No suitable VM found\n");
		return NULL;
	}

	ctl = compel_prepare_noctx(pid);
	if (!ctl)
		return NULL;

	ret = parasite_prepare_threads(ctl, item);
	if (ret)
		return NULL;

	ictx = compel_infect_ctx(ctl);

	ictx->open_proc = do_open_proc;
	ictx->child_handler = sigchld_handler;
	ictx->orig_handler.sa_handler = SIG_DFL;
	ictx->orig_handler.sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset(&ictx->orig_handler.sa_mask);
	sigaddset(&ictx->orig_handler.sa_mask, SIGCHLD);
	ictx->sock = dmpi(item)->netns->net.seqsk;
	ictx->save_regs = save_task_regs;
	ictx->make_sigframe = make_sigframe;
	ictx->regs_arg = item->core[0];
	ictx->task_size = kdat.task_size;
	ictx->syscall_ip = p;
	pr_debug("Parasite syscall_ip at %#lx\n", p);

	if (fault_injected(FI_NO_MEMFD))
		ictx->flags |= INFECT_NO_MEMFD;
	if (fault_injected(FI_PARASITE_CONNECT))
		ictx->flags |= INFECT_FAIL_CONNECT;
	if (fault_injected(FI_NO_BREAKPOINTS))
		ictx->flags |= INFECT_NO_BREAKPOINTS;
	if (kdat.compat_cr)
		ictx->flags |= INFECT_COMPATIBLE;
	if (kdat.x86_has_ptrace_fpu_xsave_bug)
		ictx->flags |= INFECT_X86_PTRACE_MXCSR_BUG;
	if (fault_injected(FI_CORRUPT_EXTREGS))
		ictx->flags |= INFECT_CORRUPT_EXTREGS;

	ictx->log_fd = log_get_fd();

	parasite_setup_c_header(ctl);

	parasite_ensure_args_size(dump_pages_args_size(vma_area_list));
	parasite_ensure_args_size(aio_rings_args_size(vma_area_list));

	if (compel_infect(ctl, item->nr_threads, parasite_args_size) < 0) {
		if (compel_cure(ctl))
			pr_warn("Can't cure failed infection\n");
		return NULL;
	}

	parasite_args_size = PARASITE_ARG_SIZE_MIN; /* reset for next task */
#ifdef CONFIG_MIPS
	memcpy(&item->core[0]->tc->blk_sigset, (unsigned long *)compel_task_sigmask(ctl),
	       sizeof(item->core[0]->tc->blk_sigset));
	memcpy(&item->core[0]->tc->blk_sigset_extended, (unsigned long *)compel_task_sigmask(ctl) + 1,
	       sizeof(item->core[0]->tc->blk_sigset));
#else
	memcpy(&item->core[0]->tc->blk_sigset, compel_task_sigmask(ctl), sizeof(k_rtsigset_t));
#endif
	dmpi(item)->parasite_ctl = ctl;

	return ctl;
}
