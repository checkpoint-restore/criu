#include <unistd.h>
#include <inttypes.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "common/config.h"
#include "common/compiler.h"
#include "types.h"
#include "protobuf.h"
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
	BUILD_BUG_ON(sizeof(ce->cap_amb[0]) != sizeof(c->cap_amb[0]));

	BUG_ON(ce->n_cap_inh != CR_CAP_SIZE);
	BUG_ON(ce->n_cap_prm != CR_CAP_SIZE);
	BUG_ON(ce->n_cap_eff != CR_CAP_SIZE);
	BUG_ON(ce->n_cap_bnd != CR_CAP_SIZE);
	BUG_ON(ce->n_cap_amb != CR_CAP_SIZE);

	memcpy(ce->cap_inh, c->cap_inh, sizeof(c->cap_inh[0]) * CR_CAP_SIZE);
	memcpy(ce->cap_prm, c->cap_prm, sizeof(c->cap_prm[0]) * CR_CAP_SIZE);
	memcpy(ce->cap_eff, c->cap_eff, sizeof(c->cap_eff[0]) * CR_CAP_SIZE);
	memcpy(ce->cap_bnd, c->cap_bnd, sizeof(c->cap_bnd[0]) * CR_CAP_SIZE);
	memcpy(ce->cap_amb, c->cap_amb, sizeof(c->cap_amb[0]) * CR_CAP_SIZE);

	if (c->no_new_privs > 0) {
		ce->no_new_privs = c->no_new_privs;
		ce->has_no_new_privs = true;
	}
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

static void init_parasite_rseq_arg(struct parasite_check_rseq *rseq)
{
	rseq->has_rseq = kdat.has_rseq;
	rseq->has_ptrace_get_rseq_conf = kdat.has_ptrace_get_rseq_conf;
	rseq->rseq_inited = false;
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

	init_parasite_rseq_arg(&args->rseq);

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
		return -1;
	}

	ret = compel_arch_fetch_thread_area(tctl);
	if (ret) {
		pr_err("Can't obtain thread area of %d\n", pid);
		return -1;
	}

	compel_arch_get_tls_thread(tctl, &args->tls);

	init_parasite_rseq_arg(&args->rseq);

	ret = compel_run_in_thread(tctl, PARASITE_CMD_DUMP_THREAD);
	if (ret) {
		pr_err("Can't init thread in parasite %d\n", pid);
		return -1;
	}

	ret = alloc_groups_copy_creds(creds, pc);
	if (ret) {
		pr_err("Can't copy creds for thread %d\n", pid);
		return -1;
	}

	tid->ns[0].virt = args->tid;
	return dump_thread_core(pid, core, args);
}

int parasite_dump_misc_seized(struct parasite_ctl *ctl, struct parasite_dump_misc *misc)
{
	struct parasite_dump_misc *ma;

	ma = compel_parasite_args(ctl, struct parasite_dump_misc);
	ma->has_membarrier_get_registrations = kdat.has_membarrier_get_registrations;
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
	memcpy(ca->thread_cgrp, cgroup->thread_cgrp, sizeof(ca->thread_cgrp));
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
