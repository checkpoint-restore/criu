#include <unistd.h>
#include <inttypes.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "protobuf.h"
#include "protobuf/sa.pb-c.h"
#include "protobuf/timer.pb-c.h"
#include "protobuf/creds.pb-c.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/pagemap.pb-c.h"

#include "syscall.h"
#include "ptrace.h"
#include "asm/processor-flags.h"
#include "parasite-syscall.h"
#include "parasite-blob.h"
#include "parasite.h"
#include "crtools.h"
#include "namespaces.h"
#include "kerndat.h"
#include "pstree.h"
#include "net.h"
#include "mem.h"
#include "vdso.h"
#include "restorer.h"
#include "proc_parse.h"

#include <string.h>
#include <stdlib.h>

#include "asm/parasite-syscall.h"
#include "asm/dump.h"
#include "asm/restorer.h"

#define parasite_size		(round_up(sizeof(parasite_blob), PAGE_SIZE))

static int can_run_syscall(unsigned long ip, unsigned long start, unsigned long end)
{
	return ip >= start && ip < (end - code_syscall_size);
}

static int syscall_fits_vma_area(struct vma_area *vma_area)
{
	return can_run_syscall((unsigned long)vma_area->vma.start,
			       (unsigned long)vma_area->vma.start,
			       (unsigned long)vma_area->vma.end);
}

static struct vma_area *get_vma_by_ip(struct list_head *vma_area_list, unsigned long ip)
{
	struct vma_area *vma_area;

	list_for_each_entry(vma_area, vma_area_list, list) {
		if (vma_area->vma.start >= TASK_SIZE)
			continue;
		if (!(vma_area->vma.prot & PROT_EXEC))
			continue;
		if (syscall_fits_vma_area(vma_area))
			return vma_area;
	}

	return NULL;
}

/* we run at @regs->ip */
int __parasite_execute_trap(struct parasite_ctl *ctl, pid_t pid,
				user_regs_struct_t *regs,
				user_regs_struct_t *regs_orig,
				bool signals_blocked)
{
	siginfo_t siginfo;
	int status;
	int ret = -1;

again:
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs)) {
		pr_perror("Can't set registers (pid: %d)", pid);
		goto err;
	}

	/*
	 * Most ideas are taken from Tejun Heo's parasite thread
	 * https://code.google.com/p/ptrace-parasite/
	 */

	if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
		pr_perror("Can't continue (pid: %d)", pid);
		goto err;
	}

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

	if (ptrace(PTRACE_GETREGS, pid, NULL, regs)) {
		pr_perror("Can't obtain registers (pid: %d)", pid);
			goto err;
	}

	if (WSTOPSIG(status) != SIGTRAP || siginfo.si_code != ARCH_SI_TRAP) {
retry_signal:
		pr_debug("** delivering signal %d si_code=%d\n",
			 siginfo.si_signo, siginfo.si_code);

		if (signals_blocked) {
			pr_err("Unexpected %d task interruption, aborting\n", pid);
			goto err;
		}

		/* FIXME: jerr(siginfo.si_code > 0, err_restore); */

		/*
		 * This requires some explanation. If a signal from original
		 * program delivered while we're trying to execute our
		 * injected blob -- we need to setup original registers back
		 * so the kernel would make sigframe for us and update the
		 * former registers.
		 *
		 * Then we should swap registers back to our modified copy
		 * and retry.
		 */

		if (ptrace(PTRACE_SETREGS, pid, NULL, regs_orig)) {
			pr_perror("Can't set registers (pid: %d)", pid);
			goto err;
		}

		if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL)) {
			pr_perror("Can't interrupt (pid: %d)", pid);
			goto err;
		}

		if (ptrace(PTRACE_CONT, pid, NULL, (void *)(unsigned long)siginfo.si_signo)) {
			pr_perror("Can't continue (pid: %d)", pid);
			goto err;
		}

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

		if (SI_EVENT(siginfo.si_code) != PTRACE_EVENT_STOP)
			goto retry_signal;

		/*
		 * Signal is delivered, so we should update
		 * original registers.
		 */
		{
			user_regs_struct_t r;
			if (ptrace(PTRACE_GETREGS, pid, NULL, &r)) {
				pr_perror("Can't obtain registers (pid: %d)", pid);
				goto err;
			}
			*regs_orig = r;
		}

		goto again;
	}

	/*
	 * We've reached this point if int3 is triggered inside our
	 * parasite code. So we're done.
	 */
	ret = 0;
err:
	return ret;
}

void *parasite_args_s(struct parasite_ctl *ctl, int args_size)
{
	BUG_ON(args_size > ctl->args_size);
	return ctl->addr_args;
}

static int parasite_execute_trap_by_pid(unsigned int cmd,
					struct parasite_ctl *ctl, pid_t pid,
					user_regs_struct_t *regs_orig,
					void *stack, bool use_sig_blocked)
{
	user_regs_struct_t regs = *regs_orig;
	int ret;

	*ctl->addr_cmd = cmd;

	parasite_setup_regs(ctl->parasite_ip, stack, &regs);

	ret = __parasite_execute_trap(ctl, pid, &regs, regs_orig, use_sig_blocked);
	if (ret == 0)
		ret = (int)REG_RES(regs);

	if (ret)
		pr_err("Parasite exited with %d\n", ret);

	if (ctl->pid.real != pid)
		if (ptrace(PTRACE_SETREGS, pid, NULL, regs_orig)) {
			pr_perror("Can't restore registers (pid: %d)", pid);
			return -1;
		}

	return ret;
}

static int parasite_execute_trap(unsigned int cmd, struct parasite_ctl *ctl)
{
	return parasite_execute_trap_by_pid(cmd, ctl, ctl->pid.real, &ctl->regs_orig,
					ctl->rstack, ctl->use_sig_blocked);
}

static int __parasite_send_cmd(int sockfd, struct ctl_msg *m)
{
	int ret;

	ret = send(sockfd, m, sizeof(*m), 0);
	if (ret == -1) {
		pr_perror("Failed to send command %d to daemon\n", m->cmd);
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

int __parasite_execute_daemon_wait_ack(unsigned int cmd,
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

int __parasite_execute_daemon(unsigned int cmd,
				struct parasite_ctl *ctl, bool wait_ack)
{
	struct ctl_msg m;

	m = ctl_msg_cmd(cmd);
	if (__parasite_send_cmd(ctl->tsock, &m))
		return -1;

	if (wait_ack)
		return __parasite_execute_daemon_wait_ack(cmd, ctl);

	return 0;
}

int parasite_execute_daemon(unsigned int cmd,
					struct parasite_ctl *ctl)
{
	return __parasite_execute_daemon(cmd, ctl, true);
}

static int munmap_seized(struct parasite_ctl *ctl, void *addr, size_t length)
{
	unsigned long x;

	return syscall_seized(ctl, __NR_munmap, &x,
			(unsigned long)addr, length, 0, 0, 0, 0);
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

static int parasite_set_logfd(struct parasite_ctl *ctl, pid_t pid)
{
	int ret;
	struct parasite_log_args *a;

	ret = parasite_send_fd(ctl, log_get_fd());
	if (ret)
		return ret;

	a = parasite_args(ctl, struct parasite_log_args);
	a->log_level = log_get_loglevel();

	ret = parasite_execute_trap(PARASITE_CMD_CFG_LOG, ctl);
	if (ret < 0)
		return ret;

	return 0;
}

static int parasite_init(struct parasite_ctl *ctl, pid_t pid, int nr_threads)
{
	static int ssock = -1;

	struct parasite_init_args *args;
	int sock;

	args = parasite_args(ctl, struct parasite_init_args);

	pr_info("Putting tsock into pid %d\n", pid);
	args->h_addr_len = gen_parasite_saddr(&args->h_addr, getpid());
	args->sigframe = ctl->rsigframe;

	if (ssock == -1) {
		int rst = -1;

		if (current_ns_mask & CLONE_NEWNET) {
			pr_info("Switching to %d's net for tsock creation\n", pid);

			if (switch_ns(pid, &net_ns_desc, &rst))
				return -1;
		}

		ssock = socket(PF_UNIX, SOCK_STREAM, 0);
		if (ssock < 0)
			pr_perror("Can't create socket");

		if (rst > 0 && restore_ns(rst, &net_ns_desc) < 0)
			return -1;
		if (ssock < 0)
			return -1;

		if (bind(ssock, (struct sockaddr *)&args->h_addr, args->h_addr_len) < 0) {
			pr_perror("Can't bind socket");
			goto err;
		}

		if (listen(ssock, 1)) {
			pr_perror("Can't listen on transport socket");
			goto err;
		}
	}

	if (parasite_execute_trap(PARASITE_CMD_INIT, ctl) < 0) {
		pr_err("Can't init parasite\n");
		goto err;
	}

	ctl->sig_blocked = args->sig_blocked;
	ctl->use_sig_blocked = true;

	sock = accept(ssock, NULL, 0);
	if (sock < 0) {
		pr_perror("Can't accept connection to the transport socket");
		goto err;
	}

	ctl->tsock = sock;
	return 0;
err:
	close_safe(&ssock);
	return -1;
}

static int parasite_daemonize(struct parasite_ctl *ctl)
{
	pid_t pid = ctl->pid.real;
	user_regs_struct_t regs;
	struct ctl_msg m = { };

	*ctl->addr_cmd = PARASITE_CMD_DAEMONIZE;

	regs = ctl->regs_orig;
	parasite_setup_regs(ctl->parasite_ip, ctl->rstack, &regs);

	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs)) {
		pr_perror("Can't set registers (pid: %d)", pid);
		goto err;
	}

	if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
		pr_perror("Can't continue (pid: %d)\n", pid);
		ptrace(PTRACE_SETREGS, pid, NULL, ctl->regs_orig);
		goto err;
	}

	pr_info("Wait for parasite being daemonized...\n");

	if (parasite_wait_ack(ctl->tsock, PARASITE_CMD_DAEMONIZE, &m)) {
		pr_err("Can't switch parasite %d to daemon mode %d\n",
		       pid, m.err);
		goto err;
	}

	ctl->daemonized = true;
	pr_info("Parasite %d has been switched to daemon mode\n", pid);
	return 0;

err:
	return -1;
}

int parasite_dump_thread_seized(struct parasite_ctl *ctl, int id,
				struct pid *tid, CoreEntry *core)
{
	struct parasite_dump_thread *args;
	int ret;

	args = parasite_args(ctl, struct parasite_dump_thread);

	if (id == 0)
		ret = parasite_execute_daemon(PARASITE_CMD_DUMP_THREAD, ctl);
	else {
		pid_t pid = tid->real;
		user_regs_struct_t regs_orig;

		ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs_orig);
		if (ret) {
			pr_perror("Can't obtain registers (pid: %d)", pid);
			return -1;
		}

		ret = parasite_execute_trap_by_pid(PARASITE_CMD_INIT_THREAD, ctl,
						pid, &regs_orig,
						ctl->r_thread_stack, false);
		if (ret) {
			pr_err("Can't init thread in parasite %d\n", pid);
			return -1;
		}

		ret = get_task_regs(pid, regs_orig, core);
		if (ret)
			pr_err("Can't obtain regs for thread %d\n", pid);

		if (parasite_execute_trap_by_pid(PARASITE_CMD_FINI_THREAD, ctl,
						pid, &regs_orig,
						ctl->r_thread_stack, true)) {
			pr_err("Can't init thread in parasite %d\n", pid);
			return -1;
		}
		if (ret)
			return -1;

		memcpy(&core->thread_core->blk_sigset,
			&args->blocked, sizeof(k_rtsigset_t));
		core->thread_core->has_blk_sigset = true;
	}

	CORE_THREAD_ARCH_INFO(core)->clear_tid_addr = encode_pointer(args->tid_addr);
	tid->virt = args->tid;
	core_put_tls(core, args->tls);

	return ret;
}

int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	struct parasite_dump_sa_args *args;
	int ret, sig, fd;
	SaEntry se = SA_ENTRY__INIT;

	args = parasite_args(ctl, struct parasite_dump_sa_args);

	ret = parasite_execute_daemon(PARASITE_CMD_DUMP_SIGACTS, ctl);
	if (ret < 0)
		return ret;

	fd = fdset_fd(cr_fdset, CR_FD_SIGACT);

	for (sig = 1; sig <= SIGMAX; sig++) {
		int i = sig - 1;

		if (sig == SIGSTOP || sig == SIGKILL)
			continue;

		ASSIGN_TYPED(se.sigaction, encode_pointer(args->sas[i].rt_sa_handler));
		ASSIGN_TYPED(se.flags, args->sas[i].rt_sa_flags);
		ASSIGN_TYPED(se.restorer, encode_pointer(args->sas[i].rt_sa_restorer));
		ASSIGN_TYPED(se.mask, args->sas[i].rt_sa_mask.sig[0]);

		if (pb_write_one(fd, &se, PB_SIGACT) < 0)
			return -1;
	}

	return 0;
}

static int dump_one_timer(struct itimerval *v, int fd)
{
	ItimerEntry ie = ITIMER_ENTRY__INIT;

	ie.isec = v->it_interval.tv_sec;
	ie.iusec = v->it_interval.tv_usec;
	ie.vsec = v->it_value.tv_sec;
	ie.vusec = v->it_value.tv_usec;

	return pb_write_one(fd, &ie, PB_ITIMERS);
}

int parasite_dump_itimers_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	struct parasite_dump_itimers_args *args;
	int ret, fd;

	args = parasite_args(ctl, struct parasite_dump_itimers_args);

	ret = parasite_execute_daemon(PARASITE_CMD_DUMP_ITIMERS, ctl);
	if (ret < 0)
		return ret;

	fd = fdset_fd(cr_fdset, CR_FD_ITIMERS);

	ret = dump_one_timer(&args->real, fd);
	if (!ret)
		ret = dump_one_timer(&args->virt, fd);
	if (!ret)
		ret = dump_one_timer(&args->prof, fd);

	return ret;
}

static int dump_one_posix_timer(struct posix_timer *v, struct proc_posix_timer *vp, int fd)
{
	PosixTimerEntry pte = POSIX_TIMER_ENTRY__INIT;

	pte.it_id = vp->spt.it_id;
	pte.clock_id = vp->spt.clock_id;
	pte.si_signo = vp->spt.si_signo;
	pte.it_sigev_notify = vp->spt.it_sigev_notify;
	pte.sival_ptr = encode_pointer(vp->spt.sival_ptr);

	pte.overrun = v->overrun;

	pte.isec = v->val.it_interval.tv_sec;
	pte.insec = v->val.it_interval.tv_nsec;
	pte.vsec = v->val.it_value.tv_sec;
	pte.vnsec = v->val.it_value.tv_nsec;

	return pb_write_one(fd, &pte, PB_POSIX_TIMERS);
}

int parasite_dump_posix_timers_seized(struct proc_posix_timers_stat *proc_args, struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	struct parasite_dump_posix_timers_args * args;
	struct proc_posix_timer *temp;
	int i, fd;
	int ret = 0;

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

	fd = fdset_fd(cr_fdset, CR_FD_POSIX_TIMERS);

	i = 0;
	list_for_each_entry(temp, &proc_args->timers, list) {
		ret = dump_one_posix_timer(&args->timer[i], temp, fd);
		i++;
		if (ret)
			goto end_posix;
	}

end_posix:
	while (!list_empty(&proc_args->timers)) {
		temp = list_first_entry(&proc_args->timers, struct proc_posix_timer, list);
		list_del(&temp->list);
		xfree(temp);
	}
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

struct parasite_tty_args *parasite_dump_tty(struct parasite_ctl *ctl, int fd)
{
	struct parasite_tty_args *p;

	p = parasite_args(ctl, struct parasite_tty_args);
	p->fd = fd;

	if (parasite_execute_daemon(PARASITE_CMD_DUMP_TTY, ctl) < 0)
		return NULL;

	return p;
}

int parasite_dump_creds(struct parasite_ctl *ctl, CredsEntry *ce)
{
	struct parasite_dump_creds *pc;

	pc = parasite_args(ctl, struct parasite_dump_creds);
	if (parasite_execute_daemon(PARASITE_CMD_DUMP_CREDS, ctl) < 0)
		return -1;

	ce->secbits = pc->secbits;
	ce->n_groups = pc->ngroups;

	/*
	 * Achtung! We leak the parasite args pointer to the caller.
	 * It's not safe in general, but in our case is OK, since the
	 * latter doesn't go to parasite before using the data in it.
	 */

	BUILD_BUG_ON(sizeof(ce->groups[0]) != sizeof(pc->groups[0]));
	ce->groups = pc->groups;
	return 0;
}

int parasite_drain_fds_seized(struct parasite_ctl *ctl,
		struct parasite_drain_fd *dfds, int *lfds, struct fd_opts *opts)
{
	int ret = -1, size;
	struct parasite_drain_fd *args;

	size = drain_fds_size(dfds);
	args = parasite_args_s(ctl, size);
	memcpy(args, dfds, size);

	ret = __parasite_execute_daemon(PARASITE_CMD_DRAIN_FDS, ctl, false);
	if (ret) {
		pr_err("Parasite failed to drain descriptors\n");
		goto err;
	}

	ret = recv_fds(ctl->tsock, lfds, dfds->nr_fds, opts);
	if (ret)
		pr_err("Can't retrieve FDs from socket\n");

	ret |= __parasite_execute_daemon_wait_ack(PARASITE_CMD_DRAIN_FDS, ctl);
err:
	return ret;
}

int parasite_get_proc_fd_seized(struct parasite_ctl *ctl)
{
	int ret = -1, fd;

	ret = __parasite_execute_daemon(PARASITE_CMD_GET_PROC_FD, ctl, false);
	if (ret) {
		pr_err("Parasite failed to get proc fd\n");
		return ret;
	}

	fd = recv_fd(ctl->tsock);
	if (fd < 0)
		pr_err("Can't retrieve FD from socket\n");
	if (__parasite_execute_daemon_wait_ack(PARASITE_CMD_GET_PROC_FD, ctl)) {
		close(fd);
		return -1;
	}

	return fd;
}


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

	if (!ctl->daemonized)
		return 0;

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

	ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	if (ret) {
		pr_perror("Unable to get registers");
		return -1;
	}

	if (!task_in_parasite(ctl, &regs)) {
		pr_err("The task is not in parasite code\n");
		return -1;
	}

	ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	if (ret) {
		pr_perror("ptrace");
		return -1;
	}

	ret = __parasite_execute_daemon(PARASITE_CMD_FINI, ctl, false);
	close_safe(&ctl->tsock);
	if (ret)
		return -1;

	/* Stop all threads on the enter point in sys_rt_sigreturn */
	while (1) {
		if (wait4(pid, &status, __WALL, NULL) < 0) {
			pr_perror("wait4 failed");
			return -1;
		}

		if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
			pr_err("Task is in unexpected state: %x\n", status);
			return -1;
		}

		pr_debug("%d was trapped\n", pid);
		if (!WIFSTOPPED(status)) {
			pr_err("%d\n", status);
			return -1;
		}
		ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		if (ret) {
			pr_perror("ptrace");
			return -1;
		}

		pr_debug("%d is going to execute the syscall %lx\n", pid, REG_SYSCALL_NR(regs));
		if (REG_SYSCALL_NR(regs) == __NR_rt_sigreturn) {
			pr_debug("%d was stopped\n", pid);
			break;
		}

		ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		if (ret) {
			pr_perror("ptrace");
			return -1;
		}
	}

	ctl->use_sig_blocked = false;

	ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	if (ret) {
		pr_perror("ptrace");
		return -1;
	}

	if (wait4(pid, &status, __WALL, NULL) != pid) {
		pr_perror("wait4 failed");
		return -1;
	}

	pr_debug("Trap %d\n", pid);
	if (!WIFSTOPPED(status)) {
		pr_err("%d\n", status);
		return -1;
	}

	return ret;
}

int parasite_cure_remote(struct parasite_ctl *ctl)
{
	int ret = 0;

	if (ctl->parasite_ip)
		if (parasite_fini_seized(ctl))
			return -1;

	close_safe(&ctl->tsock);

	if (ctl->remote_map) {
		if (munmap_seized(ctl, (void *)ctl->remote_map, ctl->map_length)) {
			pr_err("munmap_seized failed (pid: %d)\n", ctl->pid.real);
			ret = -1;
		}
	}

	if (ptrace_poke_area(ctl->pid.real, (void *)ctl->code_orig,
			     (void *)ctl->syscall_ip, sizeof(ctl->code_orig))) {
		pr_err("Can't restore syscall blob (pid: %d)\n", ctl->pid.real);
		ret = -1;
	}

	if (ptrace(PTRACE_SETREGS, ctl->pid.real, NULL, &ctl->regs_orig)) {
		pr_err("Can't restore registers (pid: %d)\n", ctl->pid.real);
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

	if (ptrace(PTRACE_GETREGS, pid, NULL, &ctl->regs_orig)) {
		pr_err("Can't obtain registers (pid: %d)\n", pid);
		goto err;
	}

	vma_area = get_vma_by_ip(&vma_area_list->h, REG_IP(ctl->regs_orig));
	if (!vma_area) {
		pr_err("No suitable VMA found to run parasite "
		       "bootstrap code (pid: %d)\n", pid);
		goto err;
	}

	ctl->pid.real	= pid;
	ctl->pid.virt	= 0;
	ctl->syscall_ip	= vma_area->vma.start;

	/*
	 * Inject syscall instruction and remember original code,
	 * we will need it to restore original program content.
	 */
	memcpy(ctl->code_orig, code_syscall, sizeof(ctl->code_orig));
	if (ptrace_swap_area(pid, (void *)ctl->syscall_ip,
			     (void *)ctl->code_orig, sizeof(ctl->code_orig))) {
		pr_err("Can't inject syscall blob (pid: %d)\n", pid);
		goto err;
	}

	return ctl;

err:
	xfree(ctl);
	return NULL;
}

int parasite_map_exchange(struct parasite_ctl *ctl, unsigned long size)
{
	int fd;

	ctl->remote_map = mmap_seized(ctl, NULL, size,
				      PROT_READ | PROT_WRITE | PROT_EXEC,
				      MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (!ctl->remote_map) {
		pr_err("Can't allocate memory for parasite blob (pid: %d)\n", ctl->pid.real);
		return -1;
	}

	ctl->map_length = round_up(size, PAGE_SIZE);

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

static unsigned long parasite_args_size(struct vm_area_list *vmas, struct parasite_drain_fd *dfds, int timer_n)
{
	unsigned long size = PARASITE_ARG_SIZE_MIN;

	if (dfds)
		size = max(size, (unsigned long)drain_fds_size(dfds));
	if (timer_n)
		size = max(size, (unsigned long)posix_timers_dump_size(timer_n));
	size = max(size, (unsigned long)dump_pages_args_size(vmas));

	return round_up(size, PAGE_SIZE);
}

struct parasite_ctl *parasite_infect_seized(pid_t pid, struct pstree_item *item,
		struct vm_area_list *vma_area_list, struct parasite_drain_fd *dfds,
		int timer_n)
{
	int ret;
	struct parasite_ctl *ctl;
	unsigned long p, map_exchange_size;

	BUG_ON(item->threads[0].real != pid);

	if (pstree_alloc_cores(item))
		return NULL;

	ctl = parasite_prep_ctl(pid, vma_area_list);
	if (!ctl)
		return NULL;

	/*
	 * Inject a parasite engine. Ie allocate memory inside alien
	 * space and copy engine code there. Then re-map the engine
	 * locally, so we will get an easy way to access engine memory
	 * without using ptrace at all.
	 */

	ctl->args_size = parasite_args_size(vma_area_list, dfds, timer_n);
	map_exchange_size = parasite_size + ctl->args_size;
	map_exchange_size += RESTORE_STACK_SIGFRAME + PARASITE_STACK_SIZE;
	if (item->nr_threads > 1)
		map_exchange_size += PARASITE_STACK_SIZE;
	ret = parasite_map_exchange(ctl, map_exchange_size);
	if (ret)
		goto err_restore;

	pr_info("Putting parasite blob into %p->%p\n", ctl->local_map, ctl->remote_map);
	memcpy(ctl->local_map, parasite_blob, sizeof(parasite_blob));

	/* Setup the rest of a control block */
	ctl->parasite_ip	= (unsigned long)parasite_sym(ctl->remote_map, __export_parasite_head_start);
	ctl->addr_cmd		= parasite_sym(ctl->local_map, __export_parasite_cmd);
	ctl->addr_args		= parasite_sym(ctl->local_map, __export_parasite_args);

	p = parasite_size + ctl->args_size;

	ctl->rsigframe	= ctl->remote_map + p;
	ctl->sigframe	= ctl->local_map  + p;

	p += RESTORE_STACK_SIGFRAME;

	ctl->rstack = ctl->remote_map + p;
	p += PARASITE_STACK_SIZE;

	if (item->nr_threads > 1) {
		ctl->r_thread_stack = ctl->remote_map + p;
		p += PARASITE_STACK_SIZE;
	}

	ret = parasite_init(ctl, pid, item->nr_threads);
	if (ret) {
		pr_err("%d: Can't create a transport socket\n", pid);
		goto err_restore;
	}

	ret = get_task_regs(pid, ctl->regs_orig, item->core[0]);
	if (ret) {
		pr_err("Can't obtain regs for thread %d\n", pid);
		goto err_restore;
	}

	ret = parasite_set_logfd(ctl, pid);
	if (ret) {
		pr_err("%d: Can't set a logging descriptor\n", pid);
		goto err_restore;
	}

	memcpy(&item->core[0]->tc->blk_sigset,
		&ctl->sig_blocked, sizeof(k_rtsigset_t));

	if (construct_sigframe(ctl->sigframe, ctl->rsigframe, item->core[0]))
		goto err_restore;

	if (parasite_daemonize(ctl))
		goto err_restore;

	return ctl;

err_restore:
	parasite_cure_seized(ctl);
	return NULL;
}

