#include <unistd.h>
#include <inttypes.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "protobuf.h"
#include "images/sa.pb-c.h"
#include "images/timer.pb-c.h"
#include "images/creds.pb-c.h"
#include "images/core.pb-c.h"
#include "images/pagemap.pb-c.h"

#include "imgset.h"
#include "ptrace.h"
#include "asm/processor-flags.h"
#include "parasite-syscall.h"
#include "parasite-blob.h"
#include "parasite.h"
#include "crtools.h"
#include "namespaces.h"
#include "kerndat.h"
#include "config.h"
#include "pstree.h"
#include "posix-timer.h"
#include "mem.h"
#include "vma.h"
#include "proc_parse.h"
#include "aio.h"
#include "fault-injection.h"

#include <string.h>
#include <stdlib.h>
#include <elf.h>

#include "asm/parasite-syscall.h"
#include "asm/dump.h"
#include "asm/restorer.h"
#include "pie/pie-relocs.h"

#define MEMFD_FNAME	"CRIUMFD"
#define MEMFD_FNAME_SZ	sizeof(MEMFD_FNAME)

static int can_run_syscall(unsigned long ip, unsigned long start,
			   unsigned long end, unsigned long pad)
{
	return ip >= start && ip < (end - BUILTIN_SYSCALL_SIZE - pad);
}

static int syscall_fits_vma_area(struct vma_area *vma_area, unsigned long pad)
{
	return can_run_syscall((unsigned long)vma_area->e->start,
			       (unsigned long)vma_area->e->start,
			       (unsigned long)vma_area->e->end,
			       pad);
}

static struct vma_area *get_vma_by_ip(struct list_head *vma_area_list,
				      unsigned long ip,
				      unsigned long pad)
{
	struct vma_area *vma_area;

	list_for_each_entry(vma_area, vma_area_list, list) {
		if (vma_area->e->start >= kdat.task_size)
			continue;
		if (!(vma_area->e->prot & PROT_EXEC))
			continue;
		if (syscall_fits_vma_area(vma_area, pad))
			return vma_area;
	}

	return NULL;
}

static inline int ptrace_get_regs(int pid, user_regs_struct_t *regs)
{
	struct iovec iov;

	iov.iov_base = regs;
	iov.iov_len = sizeof(user_regs_struct_t);
	return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
}

static inline int ptrace_set_regs(int pid, user_regs_struct_t *regs)
{
	struct iovec iov;

	iov.iov_base = regs;
	iov.iov_len = sizeof(user_regs_struct_t);
	return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

static int get_thread_ctx(int pid, struct thread_ctx *ctx)
{
	if (ptrace(PTRACE_GETSIGMASK, pid, sizeof(k_rtsigset_t), &ctx->sigmask)) {
		pr_perror("can't get signal blocking mask for %d", pid);
		return -1;
	}

	if (ptrace_get_regs(pid, &ctx->regs)) {
		pr_perror("Can't obtain registers (pid: %d)", pid);
		return -1;
	}

	return 0;
}

static int restore_thread_ctx(int pid, struct thread_ctx *ctx)
{
	int ret = 0;

	if (ptrace_set_regs(pid, &ctx->regs)) {
		pr_perror("Can't restore registers (pid: %d)", pid);
		ret = -1;
	}
	if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(k_rtsigset_t), &ctx->sigmask)) {
		pr_perror("Can't block signals");
		ret = -1;
	}

	return ret;
}

static int parasite_run(pid_t pid, int cmd, unsigned long ip, void *stack,
		user_regs_struct_t *regs, struct thread_ctx *octx)
{
	k_rtsigset_t block;

	ksigfillset(&block);
	if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(k_rtsigset_t), &block)) {
		pr_perror("Can't block signals for %d", pid);
		goto err_sig;
	}

	parasite_setup_regs(ip, stack, regs);
	if (ptrace_set_regs(pid, regs)) {
		pr_perror("Can't set registers for %d", pid);
		goto err_regs;
	}

	if (ptrace(cmd, pid, NULL, NULL)) {
		pr_perror("Can't run parasite at %d", pid);
		goto err_cont;
	}

	return 0;

err_cont:
	if (ptrace_set_regs(pid, &octx->regs))
		pr_perror("Can't restore regs for %d", pid);
err_regs:
	if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(k_rtsigset_t), &octx->sigmask))
		pr_perror("Can't restore sigmask for %d", pid);
err_sig:
	return -1;
}

/* we run at @regs->ip */
static int parasite_trap(struct parasite_ctl *ctl, pid_t pid,
				user_regs_struct_t *regs,
				struct thread_ctx *octx)
{
	siginfo_t siginfo;
	int status;
	int ret = -1;

	/*
	 * Most ideas are taken from Tejun Heo's parasite thread
	 * https://code.google.com/p/ptrace-parasite/
	 */

	if (wait4(pid, &status, __WALL, NULL) != pid) {
		pr_perror("Waited pid mismatch (pid: %d)", pid);
		goto err;
	}

	if (!WIFSTOPPED(status)) {
		pr_err("Task is still running (pid: %d)\n", pid);
		goto err;
	}

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)) {
		pr_perror("Can't get siginfo (pid: %d)", pid);
		goto err;
	}

	if (ptrace_get_regs(pid, regs)) {
		pr_perror("Can't obtain registers (pid: %d)", pid);
			goto err;
	}

	if (WSTOPSIG(status) != SIGTRAP || siginfo.si_code != ARCH_SI_TRAP) {
		pr_debug("** delivering signal %d si_code=%d\n",
			 siginfo.si_signo, siginfo.si_code);

		pr_err("Unexpected %d task interruption, aborting\n", pid);
		goto err;
	}

	/*
	 * We've reached this point if int3 is triggered inside our
	 * parasite code. So we're done.
	 */
	ret = 0;
err:
	if (restore_thread_ctx(pid, octx))
		ret = -1;

	return ret;
}

int __parasite_execute_syscall(struct parasite_ctl *ctl,
		user_regs_struct_t *regs, const char *code_syscall)
{
	pid_t pid = ctl->pid.real;
	int err;
	u8 code_orig[BUILTIN_SYSCALL_SIZE];

	/*
	 * Inject syscall instruction and remember original code,
	 * we will need it to restore original program content.
	 */
	memcpy(code_orig, code_syscall, sizeof(code_orig));
	if (ptrace_swap_area(pid, (void *)ctl->syscall_ip,
			     (void *)code_orig, sizeof(code_orig))) {
		pr_err("Can't inject syscall blob (pid: %d)\n", pid);
		return -1;
	}

	err = parasite_run(pid, PTRACE_CONT, ctl->syscall_ip, 0, regs, &ctl->orig);
	if (!err)
		err = parasite_trap(ctl, pid, regs, &ctl->orig);

	if (ptrace_poke_area(pid, (void *)code_orig,
			     (void *)ctl->syscall_ip, sizeof(code_orig))) {
		pr_err("Can't restore syscall blob (pid: %d)\n", ctl->pid.real);
		err = -1;
	}

	return err;
}

void *parasite_args_s(struct parasite_ctl *ctl, int args_size)
{
	BUG_ON(args_size > ctl->args_size);
	return ctl->addr_args;
}

static int parasite_execute_trap_by_pid(unsigned int cmd,
					struct parasite_ctl *ctl, pid_t pid,
					void *stack,
					struct thread_ctx *octx)
{
	user_regs_struct_t regs = octx->regs;
	int ret;

	*ctl->addr_cmd = cmd;

	ret = parasite_run(pid, PTRACE_CONT, ctl->parasite_ip, stack, &regs, octx);
	if (ret == 0)
		ret = parasite_trap(ctl, pid, &regs, octx);
	if (ret == 0)
		ret = (int)REG_RES(regs);

	if (ret)
		pr_err("Parasite exited with %d\n", ret);

	return ret;
}

static int __parasite_send_cmd(int sockfd, struct ctl_msg *m)
{
	int ret;

	ret = send(sockfd, m, sizeof(*m), 0);
	if (ret == -1) {
		pr_perror("Failed to send command %d to daemon", m->cmd);
		return -1;
	} else if (ret != sizeof(*m)) {
		pr_err("Message to daemon is trimmed (%d/%d)\n",
		       (int)sizeof(*m), ret);
		return -1;
	}

	pr_debug("Sent msg to daemon %d %d %d\n", m->cmd, m->ack, m->err);
	return 0;
}

static int parasite_wait_ack(int sockfd, unsigned int cmd, struct ctl_msg *m)
{
	int ret;

	pr_debug("Wait for ack %d on daemon socket\n", cmd);

	while (1) {
		memzero(m, sizeof(*m));

		ret = recv(sockfd, m, sizeof(*m), MSG_WAITALL);
		if (ret == -1) {
			pr_perror("Failed to read ack");
			return -1;
		} else if (ret != sizeof(*m)) {
			pr_err("Message reply from daemon is trimmed (%d/%d)\n",
			       (int)sizeof(*m), ret);
			return -1;
		}
		pr_debug("Fetched ack: %d %d %d\n",
			 m->cmd, m->ack, m->err);

		if (m->cmd != cmd || m->ack != cmd) {
			pr_err("Communication error, this is not "
			       "the ack we expected\n");
			return -1;
		}
		return 0;
	}

	return -1;
}

int __parasite_wait_daemon_ack(unsigned int cmd,
					struct parasite_ctl *ctl)
{
	struct ctl_msg m;

	if (parasite_wait_ack(ctl->tsock, cmd, &m))
		return -1;

	if (m.err != 0) {
		pr_err("Command %d for daemon failed with %d\n",
		       cmd, m.err);
		return -1;
	}

	return 0;
}

int __parasite_execute_daemon(unsigned int cmd, struct parasite_ctl *ctl)
{
	struct ctl_msg m;

	m = ctl_msg_cmd(cmd);
	return __parasite_send_cmd(ctl->tsock, &m);
}

int parasite_execute_daemon(unsigned int cmd, struct parasite_ctl *ctl)
{
	int ret;

	ret = __parasite_execute_daemon(cmd, ctl);
	if (!ret)
		ret = __parasite_wait_daemon_ack(cmd, ctl);

	return ret;
}

static int gen_parasite_saddr(struct sockaddr_un *saddr, int key)
{
	int sun_len;

	saddr->sun_family = AF_UNIX;
	snprintf(saddr->sun_path, UNIX_PATH_MAX,
			"X/crtools-pr-%d", key);

	sun_len = SUN_LEN(saddr);
	*saddr->sun_path = '\0';

	return sun_len;
}

int parasite_send_fd(struct parasite_ctl *ctl, int fd)
{
	if (send_fd(ctl->tsock, NULL, 0, fd) < 0) {
		pr_perror("Can't send file descriptor");
		return -1;
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

	pr_err("si_code=%d si_pid=%d si_status=%d\n",
		siginfo->si_code, siginfo->si_pid, siginfo->si_status);

	if (WIFEXITED(status))
		pr_err("%d exited with %d unexpectedly\n", pid, WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		pr_err("%d was killed by %d unexpectedly: %s\n",
			pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
	else if (WIFSTOPPED(status))
		pr_err("%d was stopped by %d unexpectedly\n", pid, WSTOPSIG(status));

	exit(1);
}

static int setup_child_handler()
{
	struct sigaction sa = {
		.sa_sigaction	= sigchld_handler,
		.sa_flags	= SA_SIGINFO | SA_RESTART,
	};

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGCHLD);
	if (sigaction(SIGCHLD, &sa, NULL)) {
		pr_perror("Unable to setup SIGCHLD handler");
		return -1;
	}

	return 0;
}

static int restore_child_handler()
{
	struct sigaction sa = {
		.sa_handler	= SIG_DFL,
		.sa_flags	= SA_SIGINFO | SA_RESTART,
	};

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGCHLD);
	if (sigaction(SIGCHLD, &sa, NULL)) {
		pr_perror("Unable to setup SIGCHLD handler");
		return -1;
	}

	return 0;
}

static int prepare_tsock(struct parasite_ctl *ctl, pid_t pid,
		struct parasite_init_args *args, struct ns_id *net)
{
	static int ssock = -1;

	pr_info("Putting tsock into pid %d\n", pid);
	args->h_addr_len = gen_parasite_saddr(&args->h_addr, getpid());

	if (ssock == -1) {
		ssock = net->net.seqsk;
		net->net.seqsk = -1;

		if (bind(ssock, (struct sockaddr *)&args->h_addr, args->h_addr_len) < 0) {
			pr_perror("Can't bind socket");
			goto err;
		}

		if (listen(ssock, 1)) {
			pr_perror("Can't listen on transport socket");
			goto err;
		}
	}

	/*
	 * Set to -1 to prevent any accidental misuse. The
	 * only valid user of it is accept_tsock().
	 */
	ctl->tsock = -ssock;
	return 0;
err:
	close_safe(&ssock);
	return -1;
}

static int accept_tsock(struct parasite_ctl *ctl)
{
	int sock;
	int ask = -ctl->tsock; /* this '-' is explained above */

	sock = accept(ask, NULL, 0);
	if (sock < 0) {
		pr_perror("Can't accept connection to the transport socket");
		close(ask);
		return -1;
	}

	ctl->tsock = sock;
	return 0;
}

static int parasite_init_daemon(struct parasite_ctl *ctl, struct ns_id *net)
{
	struct parasite_init_args *args;
	pid_t pid = ctl->pid.real;
	user_regs_struct_t regs;
	struct ctl_msg m = { };

	*ctl->addr_cmd = PARASITE_CMD_INIT_DAEMON;

	args = parasite_args(ctl, struct parasite_init_args);

	args->sigframe = ctl->rsigframe;
	args->log_level = log_get_loglevel();

	if (prepare_tsock(ctl, pid, args, net))
		goto err;

	/* after this we can catch parasite errors in chld handler */
	if (setup_child_handler())
		goto err;

	regs = ctl->orig.regs;
	if (parasite_run(pid, PTRACE_CONT, ctl->parasite_ip, ctl->rstack, &regs, &ctl->orig))
		goto err;

	if (accept_tsock(ctl) < 0)
		goto err;

	if (parasite_send_fd(ctl, log_get_fd()))
		goto err;

	pr_info("Wait for parasite being daemonized...\n");

	if (parasite_wait_ack(ctl->tsock, PARASITE_CMD_INIT_DAEMON, &m)) {
		pr_err("Can't switch parasite %d to daemon mode %d\n",
		       pid, m.err);
		goto err;
	}

	ctl->sigreturn_addr = args->sigreturn_addr;
	ctl->daemonized = true;
	pr_info("Parasite %d has been switched to daemon mode\n", pid);
	return 0;
err:
	return -1;
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

	ce->secbits	= c->secbits;
	ce->n_groups	= c->ngroups;

	ce->groups	= xmemdup(c->groups, sizeof(c->groups[0]) * c->ngroups);

	ce->uid		= c->uids[0];
	ce->gid		= c->gids[0];
	ce->euid	= c->uids[1];
	ce->egid	= c->gids[1];
	ce->suid	= c->uids[2];
	ce->sgid	= c->gids[2];
	ce->fsuid	= c->uids[3];
	ce->fsgid	= c->gids[3];

	return ce->groups ? 0 : -ENOMEM;
}

int parasite_dump_thread_leader_seized(struct parasite_ctl *ctl, int pid, CoreEntry *core)
{
	ThreadCoreEntry *tc = core->thread_core;
	struct parasite_dump_thread *args;
	struct parasite_dump_creds *pc;
	int ret;

	args = parasite_args(ctl, struct parasite_dump_thread);

	pc = args->creds;
	pc->cap_last_cap = kdat.last_cap;

	ret = parasite_execute_daemon(PARASITE_CMD_DUMP_THREAD, ctl);
	if (ret < 0)
		return ret;

	ret = alloc_groups_copy_creds(tc->creds, pc);
	if (ret) {
		pr_err("Can't copy creds for thread leader %d\n", pid);
		return -1;
	}

	return dump_thread_core(pid, core, args);
}

int parasite_dump_thread_seized(struct parasite_ctl *ctl, int id,
				struct pid *tid, CoreEntry *core)
{
	struct parasite_dump_thread *args;
	pid_t pid = tid->real;
	ThreadCoreEntry *tc = core->thread_core;
	CredsEntry *creds = tc->creds;
	struct parasite_dump_creds *pc;
	int ret;
	struct thread_ctx octx;

	BUG_ON(id == 0); /* Leader is dumped in dump_task_core_all */

	args = parasite_args(ctl, struct parasite_dump_thread);

	pc = args->creds;
	pc->cap_last_cap = kdat.last_cap;

	ret = get_thread_ctx(pid, &octx);
	if (ret)
		return -1;

	tc->has_blk_sigset = true;
	memcpy(&tc->blk_sigset, &octx.sigmask, sizeof(k_rtsigset_t));

	ret = parasite_execute_trap_by_pid(PARASITE_CMD_DUMP_THREAD, ctl,
			pid, ctl->r_thread_stack, &octx);
	if (ret) {
		pr_err("Can't init thread in parasite %d\n", pid);
		return -1;
	}

	ret = alloc_groups_copy_creds(creds, pc);
	if (ret) {
		pr_err("Can't copy creds for thread %d\n", pid);
		return -1;
	}

	ret = get_task_regs(pid, octx.regs, core);
	if (ret) {
		pr_err("Can't obtain regs for thread %d\n", pid);
		return -1;
	}

	tid->virt = args->tid;
	return dump_thread_core(pid, core, args);
}

int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct cr_imgset *cr_imgset)
{
	struct parasite_dump_sa_args *args;
	int ret, sig;
	struct cr_img *img;
	SaEntry se = SA_ENTRY__INIT;

	args = parasite_args(ctl, struct parasite_dump_sa_args);

	ret = parasite_execute_daemon(PARASITE_CMD_DUMP_SIGACTS, ctl);
	if (ret < 0)
		return ret;

	img = img_from_set(cr_imgset, CR_FD_SIGACT);

	for (sig = 1; sig <= SIGMAX; sig++) {
		int i = sig - 1;

		if (sig == SIGSTOP || sig == SIGKILL)
			continue;

		ASSIGN_TYPED(se.sigaction, encode_pointer(args->sas[i].rt_sa_handler));
		ASSIGN_TYPED(se.flags, args->sas[i].rt_sa_flags);
		ASSIGN_TYPED(se.restorer, encode_pointer(args->sas[i].rt_sa_restorer));
		ASSIGN_TYPED(se.mask, args->sas[i].rt_sa_mask.sig[0]);

		if (pb_write_one(img, &se, PB_SIGACT) < 0)
			return -1;
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

	args = parasite_args(ctl, struct parasite_dump_itimers_args);

	ret = parasite_execute_daemon(PARASITE_CMD_DUMP_ITIMERS, ctl);
	if (ret < 0)
		return ret;

	encode_itimer(&args->real, core->tc->timers->real);
	encode_itimer(&args->virt, core->tc->timers->virt);
	encode_itimer(&args->prof, core->tc->timers->prof);

	return 0;
}

static void encode_posix_timer(struct posix_timer *v, struct proc_posix_timer *vp, PosixTimerEntry *pte)
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
}

static int core_alloc_posix_timers(TaskTimersEntry *tte, int n,
		PosixTimerEntry **pte)
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

int parasite_dump_posix_timers_seized(struct proc_posix_timers_stat *proc_args,
		struct parasite_ctl *ctl, struct pstree_item *item)
{
	CoreEntry *core = item->core[0];
	TaskTimersEntry *tte = core->tc->timers;
	PosixTimerEntry *pte;
	struct parasite_dump_posix_timers_args * args;
	struct proc_posix_timer *temp;
	int i;
	int ret = 0;

	if (core_alloc_posix_timers(tte, proc_args->timer_n, &pte))
		return -1;

	args = parasite_args_s(ctl, posix_timers_dump_size(proc_args->timer_n));
	args->timer_n = proc_args->timer_n;

	i = 0;
	list_for_each_entry(temp, &proc_args->timers, list) {
		args->timer[i].it_id = temp->spt.it_id;
		i++;
	}

	ret = parasite_execute_daemon(PARASITE_CMD_DUMP_POSIX_TIMERS, ctl);
	if (ret < 0)
		goto end_posix;

	i = 0;
	list_for_each_entry(temp, &proc_args->timers, list) {
		posix_timer_entry__init(&pte[i]);
		encode_posix_timer(&args->timer[i], temp, &pte[i]);
		tte->posix[i] = &pte[i];
		i++;
	}

end_posix:
	free_posix_timers(proc_args);
	return ret;
}

int parasite_dump_misc_seized(struct parasite_ctl *ctl, struct parasite_dump_misc *misc)
{
	struct parasite_dump_misc *ma;

	ma = parasite_args(ctl, struct parasite_dump_misc);
	if (parasite_execute_daemon(PARASITE_CMD_DUMP_MISC, ctl) < 0)
		return -1;

	*misc = *ma;
	return 0;
}

struct parasite_tty_args *parasite_dump_tty(struct parasite_ctl *ctl, int fd, int type)
{
	struct parasite_tty_args *p;

	p = parasite_args(ctl, struct parasite_tty_args);
	p->fd = fd;
	p->type = type;

	if (parasite_execute_daemon(PARASITE_CMD_DUMP_TTY, ctl) < 0)
		return NULL;

	return p;
}

int parasite_drain_fds_seized(struct parasite_ctl *ctl,
		struct parasite_drain_fd *dfds, int nr_fds, int off,
		int *lfds, struct fd_opts *opts)
{
	int ret = -1, size;
	struct parasite_drain_fd *args;

	size = drain_fds_size(dfds);
	args = parasite_args_s(ctl, size);
	args->nr_fds = nr_fds;
	memcpy(&args->fds, dfds->fds + off, sizeof(int) * nr_fds);

	ret = __parasite_execute_daemon(PARASITE_CMD_DRAIN_FDS, ctl);
	if (ret) {
		pr_err("Parasite failed to drain descriptors\n");
		goto err;
	}

	ret = recv_fds(ctl->tsock, lfds, nr_fds, opts);
	if (ret)
		pr_err("Can't retrieve FDs from socket\n");

	ret |= __parasite_wait_daemon_ack(PARASITE_CMD_DRAIN_FDS, ctl);
err:
	return ret;
}

int parasite_get_proc_fd_seized(struct parasite_ctl *ctl)
{
	int ret = -1, fd;

	ret = __parasite_execute_daemon(PARASITE_CMD_GET_PROC_FD, ctl);
	if (ret) {
		pr_err("Parasite failed to get proc fd\n");
		return ret;
	}

	fd = recv_fd(ctl->tsock);
	if (fd < 0)
		pr_err("Can't retrieve FD from socket\n");
	if (__parasite_wait_daemon_ack(PARASITE_CMD_GET_PROC_FD, ctl)) {
		close_safe(&fd);
		return -1;
	}

	return fd;
}

/* This is officially the 50000'th line in the CRIU source code */

static bool task_in_parasite(struct parasite_ctl *ctl, user_regs_struct_t *regs)
{
	void *addr = (void *) REG_IP(*regs);
	return addr >= ctl->remote_map &&
		addr < ctl->remote_map + ctl->map_length;
}

static int parasite_fini_seized(struct parasite_ctl *ctl)
{
	pid_t pid = ctl->pid.real;
	user_regs_struct_t regs;
	int status, ret = 0;
	enum trace_flags flag;

	/* stop getting chld from parasite -- we're about to step-by-step it */
	if (restore_child_handler())
		return -1;

	/* Start to trace syscalls for each thread */
	if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL)) {
		pr_perror("Unable to interrupt the process");
		return -1;
	}

	pr_debug("Waiting for %d to trap\n", pid);
	if (wait4(pid, &status, __WALL, NULL) != pid) {
		pr_perror("Waited pid mismatch (pid: %d)", pid);
		return -1;
	}

	pr_debug("Daemon %d exited trapping\n", pid);
	if (!WIFSTOPPED(status)) {
		pr_err("Task is still running (pid: %d)\n", pid);
		return -1;
	}

	ret = ptrace_get_regs(pid, &regs);
	if (ret) {
		pr_perror("Unable to get registers");
		return -1;
	}

	if (!task_in_parasite(ctl, &regs)) {
		pr_err("The task is not in parasite code\n");
		return -1;
	}

	ret = __parasite_execute_daemon(PARASITE_CMD_FINI, ctl);
	close_safe(&ctl->tsock);
	if (ret)
		return -1;

	/* Go to sigreturn as closer as we can */
	ret = ptrace_stop_pie(pid, ctl->sigreturn_addr, &flag);
	if (ret < 0)
		return ret;

	if (parasite_stop_on_syscall(1, __NR_rt_sigreturn, flag))
		return -1;

	if (ptrace_flush_breakpoints(pid))
		return -1;

	/*
	 * All signals are unblocked now. The kernel notifies about leaving
	 * syscall before starting to deliver signals. All parasite code are
	 * executed with blocked signals, so we can sefly unmap a parasite blob.
	 */

	return 0;
}

static bool task_is_trapped(int status, pid_t pid)
{
	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
		return true;

	pr_err("Task %d is in unexpected state: %x\n", pid, status);
	if (WIFEXITED(status))
		pr_err("Task exited with %d\n", WEXITSTATUS(status));
	if (WIFSIGNALED(status))
		pr_err("Task signaled with %d: %s\n",
			WTERMSIG(status), strsignal(WTERMSIG(status)));
	if (WIFSTOPPED(status))
		pr_err("Task stopped with %d: %s\n",
			WSTOPSIG(status), strsignal(WSTOPSIG(status)));
	if (WIFCONTINUED(status))
		pr_err("Task continued\n");

	return false;
}

/*
 * Trap tasks on the exit from the specified syscall
 *
 * tasks - number of processes, which should be trapped
 * sys_nr - the required syscall number
 */
int parasite_stop_on_syscall(int tasks, const int sys_nr, enum trace_flags trace)
{
	user_regs_struct_t regs;
	int status, ret;
	pid_t pid;

	if (tasks > 1)
		trace = TRACE_ALL;

	/* Stop all threads on the enter point in sys_rt_sigreturn */
	while (tasks) {
		pid = wait4(-1, &status, __WALL, NULL);
		if (pid == -1) {
			pr_perror("wait4 failed");
			return -1;
		}

		if (!task_is_trapped(status, pid))
			return -1;

		pr_debug("%d was trapped\n", pid);

		if (trace == TRACE_EXIT) {
			trace = TRACE_ENTER;
			pr_debug("`- Expecting exit\n");
			goto goon;
		}
		if (trace == TRACE_ENTER)
			trace = TRACE_EXIT;

		ret = ptrace_get_regs(pid, &regs);
		if (ret) {
			pr_perror("ptrace");
			return -1;
		}

		pr_debug("%d is going to execute the syscall %lu\n", pid, REG_SYSCALL_NR(regs));
		if (REG_SYSCALL_NR(regs) == sys_nr) {
			/*
			 * The process is going to execute the required syscall,
			 * the next stop will be on the exit from this syscall
			 */
			ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
			if (ret) {
				pr_perror("ptrace");
				return -1;
			}

			pid = wait4(pid, &status, __WALL, NULL);
			if (pid == -1) {
				pr_perror("wait4 failed");
				return -1;
			}

			if (!task_is_trapped(status, pid))
				return -1;

			pr_debug("%d was stopped\n", pid);
			tasks--;
			continue;
		}
goon:
		ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		if (ret) {
			pr_perror("ptrace");
			return -1;
		}
	}

	return 0;
}

int parasite_stop_daemon(struct parasite_ctl *ctl)
{
	if (ctl->daemonized) {
		/*
		 * Looks like a previous attempt failed, we should do
		 * nothing in this case. parasite will try to cure itself.
		 */
		if (ctl->tsock < 0)
			return -1;

		if (parasite_fini_seized(ctl)) {
			close_safe(&ctl->tsock);
			return -1;
		}
	}

	ctl->daemonized = false;

	return 0;
}

int parasite_cure_remote(struct parasite_ctl *ctl)
{
	int ret = 0;

	if (parasite_stop_daemon(ctl))
		return -1;

	if (ctl->remote_map) {
		struct parasite_unmap_args *args;

		*ctl->addr_cmd = PARASITE_CMD_UNMAP;

		args = parasite_args(ctl, struct parasite_unmap_args);
		args->parasite_start = ctl->remote_map;
		args->parasite_len = ctl->map_length;
		if (parasite_unmap(ctl, ctl->parasite_ip))
			ret = -1;
	}

	return ret;
}

int parasite_cure_local(struct parasite_ctl *ctl)
{
	int ret = 0;

	if (ctl->local_map) {
		if (munmap(ctl->local_map, ctl->map_length)) {
			pr_err("munmap failed (pid: %d)\n", ctl->pid.real);
			ret = -1;
		}
	}

	free(ctl);
	return ret;
}

int parasite_cure_seized(struct parasite_ctl *ctl)
{
	int ret;

	ret = parasite_cure_remote(ctl);
	if (!ret)
		ret = parasite_cure_local(ctl);

	return ret;
}

/*
 * parasite_unmap() is used for unmapping parasite and restorer blobs.
 * A blob can contain code for unmapping itself, so the porcess is
 * trapped on the exit from the munmap syscall.
 */
int parasite_unmap(struct parasite_ctl *ctl, unsigned long addr)
{
	user_regs_struct_t regs = ctl->orig.regs;
	pid_t pid = ctl->pid.real;
	int ret = -1;

	ret = parasite_run(pid, PTRACE_SYSCALL, addr, NULL, &regs, &ctl->orig);
	if (ret)
		goto err;

	ret = parasite_stop_on_syscall(1, __NR_munmap, TRACE_ENTER);

	if (restore_thread_ctx(pid, &ctl->orig))
		ret = -1;
err:
	return ret;
}

/* If vma_area_list is NULL, a place for injecting syscall will not be set. */
struct parasite_ctl *parasite_prep_ctl(pid_t pid, struct vm_area_list *vma_area_list)
{
	struct parasite_ctl *ctl = NULL;
	struct vma_area *vma_area;

	if (!arch_can_dump_task(pid))
		goto err;

	/*
	 * Control block early setup.
	 */
	ctl = xzalloc(sizeof(*ctl));
	if (!ctl) {
		pr_err("Parasite control block allocation failed (pid: %d)\n", pid);
		goto err;
	}

	ctl->tsock = -1;

	if (get_thread_ctx(pid, &ctl->orig))
		goto err;

	ctl->pid.real	= pid;
	ctl->pid.virt	= 0;

	if (vma_area_list == NULL)
		return ctl;

	/* Search a place for injecting syscall */
	vma_area = get_vma_by_ip(&vma_area_list->h, REG_IP(ctl->orig.regs),
				 MEMFD_FNAME_SZ);
	if (!vma_area) {
		pr_err("No suitable VMA found to run parasite "
		       "bootstrap code (pid: %d)\n", pid);
		goto err;
	}

	ctl->syscall_ip	= vma_area->e->start;
	pr_debug("Parasite syscall_ip at %p\n", (void *)ctl->syscall_ip);

	return ctl;

err:
	xfree(ctl);
	return NULL;
}

static int parasite_mmap_exchange(struct parasite_ctl *ctl, unsigned long size)
{
	int fd;

	ctl->remote_map = mmap_seized(ctl, NULL, size,
				      PROT_READ | PROT_WRITE | PROT_EXEC,
				      MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (!ctl->remote_map) {
		pr_err("Can't allocate memory for parasite blob (pid: %d)\n", ctl->pid.real);
		return -1;
	}

	ctl->map_length = round_up(size, page_size());

	fd = open_proc_rw(ctl->pid.real, "map_files/%p-%p",
		 ctl->remote_map, ctl->remote_map + ctl->map_length);
	if (fd < 0)
		return -1;

	ctl->local_map = mmap(NULL, size, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_FILE, fd, 0);
	close(fd);

	if (ctl->local_map == MAP_FAILED) {
		ctl->local_map = NULL;
		pr_perror("Can't map remote parasite map");
		return -1;
	}

	return 0;
}

#ifdef CONFIG_HAS_MEMFD
static int parasite_memfd_exchange(struct parasite_ctl *ctl, unsigned long size)
{
	void *where = (void *)ctl->syscall_ip + BUILTIN_SYSCALL_SIZE;
	u8 orig_code[MEMFD_FNAME_SZ] = MEMFD_FNAME;
	pid_t pid = ctl->pid.real;
	unsigned long sret = -ENOSYS;
	int ret, fd, lfd;

	if (fault_injected(FI_NO_MEMFD))
		return 1;

	BUILD_BUG_ON(sizeof(orig_code) < sizeof(long));

	if (ptrace_swap_area(pid, where, (void *)orig_code, sizeof(orig_code))) {
		pr_err("Can't inject memfd args (pid: %d)\n", pid);
		return -1;
	}

	ret = syscall_seized(ctl, __NR_memfd_create, &sret,
			     (unsigned long)where, 0, 0, 0, 0, 0);

	if (ptrace_poke_area(pid, orig_code, where, sizeof(orig_code))) {
		fd = (int)(long)sret;
		if (fd >= 0)
			syscall_seized(ctl, __NR_close, &sret, fd, 0, 0, 0, 0, 0);
		pr_err("Can't restore memfd args (pid: %d)\n", pid);
		return -1;
	}

	if (ret < 0)
		return ret;

	fd = (int)(long)sret;
	if (fd == -ENOSYS)
		return 1;
	if (fd < 0)
		return fd;

	ctl->map_length = round_up(size, page_size());
	lfd = open_proc_rw(ctl->pid.real, "fd/%d", fd);
	if (lfd < 0)
		goto err_cure;

	if (ftruncate(lfd, ctl->map_length) < 0) {
		pr_perror("Fail to truncate memfd for parasite");
		goto err_cure;
	}

	ctl->remote_map = mmap_seized(ctl, NULL, size,
				      PROT_READ | PROT_WRITE | PROT_EXEC,
				      MAP_FILE | MAP_SHARED, fd, 0);
	if (!ctl->remote_map) {
		pr_err("Can't rmap memfd for parasite blob\n");
		goto err_curef;
	}

	ctl->local_map = mmap(NULL, size, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_FILE, lfd, 0);
	if (ctl->local_map == MAP_FAILED) {
		ctl->local_map = NULL;
		pr_perror("Can't lmap memfd for parasite blob");
		goto err_curef;
	}

	syscall_seized(ctl, __NR_close, &sret, fd, 0, 0, 0, 0, 0);
	close(lfd);

	pr_info("Set up parasite blob using memfd\n");
	return 0;

err_curef:
	close(lfd);
err_cure:
	syscall_seized(ctl, __NR_close, &sret, fd, 0, 0, 0, 0, 0);
	return -1;
}
#else
static int parasite_memfd_exchange(struct parasite_ctl *ctl, unsigned long size)
{
	return 1;
}
#endif

int parasite_map_exchange(struct parasite_ctl *ctl, unsigned long size)
{
	int ret;

	ret = parasite_memfd_exchange(ctl, size);
	if (ret == 1) {
		pr_info("MemFD parasite doesn't work, goto legacy mmap\n");
		ret = parasite_mmap_exchange(ctl, size);
	}
	return ret;
}

int parasite_dump_cgroup(struct parasite_ctl *ctl, struct parasite_dump_cgroup_args *cgroup)
{
	int ret;
	struct parasite_dump_cgroup_args *ca;

	ca = parasite_args(ctl, struct parasite_dump_cgroup_args);
	ret = parasite_execute_daemon(PARASITE_CMD_DUMP_CGROUP, ctl);
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

static int parasite_start_daemon(struct parasite_ctl *ctl, struct pstree_item *item)
{
	pid_t pid = ctl->pid.real;

	/*
	 * Get task registers before going daemon, since the
	 * get_task_regs needs to call ptrace on _stopped_ task,
	 * while in daemon it is not such.
	 */

	if (get_task_regs(pid, ctl->orig.regs, item->core[0])) {
		pr_err("Can't obtain regs for thread %d\n", pid);
		return -1;
	}

	if (construct_sigframe(ctl->sigframe, ctl->rsigframe, item->core[0]))
		return -1;

	if (parasite_init_daemon(ctl, dmpi(item)->netns))
		return -1;

	return 0;
}

struct parasite_ctl *parasite_infect_seized(pid_t pid, struct pstree_item *item,
		struct vm_area_list *vma_area_list)
{
	int ret;
	struct parasite_ctl *ctl;
	unsigned long p, map_exchange_size;

	BUG_ON(item->threads[0].real != pid);

	ctl = parasite_prep_ctl(pid, vma_area_list);
	if (!ctl)
		return NULL;

	parasite_ensure_args_size(dump_pages_args_size(vma_area_list));
	parasite_ensure_args_size(aio_rings_args_size(vma_area_list));

	/*
	 * Inject a parasite engine. Ie allocate memory inside alien
	 * space and copy engine code there. Then re-map the engine
	 * locally, so we will get an easy way to access engine memory
	 * without using ptrace at all.
	 */

	ctl->args_size = round_up(parasite_args_size, PAGE_SIZE);
	parasite_args_size = PARASITE_ARG_SIZE_MIN; /* reset for next task */
	map_exchange_size = pie_size(parasite_blob) + ctl->args_size;
	map_exchange_size += RESTORE_STACK_SIGFRAME + PARASITE_STACK_SIZE;
	if (item->nr_threads > 1)
		map_exchange_size += PARASITE_STACK_SIZE;

	memcpy(&item->core[0]->tc->blk_sigset, &ctl->orig.sigmask, sizeof(k_rtsigset_t));

	ret = parasite_map_exchange(ctl, map_exchange_size);
	if (ret)
		goto err_restore;

	pr_info("Putting parasite blob into %p->%p\n", ctl->local_map, ctl->remote_map);
	memcpy(ctl->local_map, parasite_blob, sizeof(parasite_blob));

	ELF_RELOCS_APPLY_PARASITE(ctl->local_map, ctl->remote_map);

	/* Setup the rest of a control block */
	ctl->parasite_ip	= (unsigned long)parasite_sym(ctl->remote_map, __export_parasite_head_start);
	ctl->addr_cmd		= parasite_sym(ctl->local_map, __export_parasite_cmd);
	ctl->addr_args		= parasite_sym(ctl->local_map, __export_parasite_args);

	p = pie_size(parasite_blob) + ctl->args_size;

	ctl->rsigframe	= ctl->remote_map + p;
	ctl->sigframe	= ctl->local_map  + p;

	p += RESTORE_STACK_SIGFRAME;
	p += PARASITE_STACK_SIZE;
	ctl->rstack = ctl->remote_map + p;

	if (item->nr_threads > 1) {
		p += PARASITE_STACK_SIZE;
		ctl->r_thread_stack = ctl->remote_map + p;
	}

	if (parasite_start_daemon(ctl, item))
		goto err_restore;

	return ctl;

err_restore:
	parasite_cure_seized(ctl);
	return NULL;
}

int ptrace_stop_pie(pid_t pid, void *addr, enum trace_flags *tf)
{
	int ret;

	if (fault_injected(FI_NO_BREAKPOINTS)) {
		pr_debug("Force no-breakpoints restore\n");
		ret = 0;
	} else
		ret = ptrace_set_breakpoint(pid, addr);
	if (ret < 0)
		return ret;

	if (ret > 0) {
		/*
		 * PIE will stop on a breakpoint, next
		 * stop after that will be syscall enter.
		 */
		*tf = TRACE_EXIT;
		return 0;
	}

	/*
	 * No breakpoints available -- start tracing it
	 * in a per-syscall manner.
	 */
	ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	if (ret) {
		pr_perror("Unable to restart the %d process", pid);
		return -1;
	}

	*tf = TRACE_ENTER;
	return 0;
}
