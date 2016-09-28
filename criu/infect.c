#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <linux/seccomp.h>

#include "ptrace.h"
#include "signal.h"
#include "asm/parasite-syscall.h"
#include "asm/dump.h"
#include "restorer.h"
#include "parasite.h"
#include "parasite-syscall.h"
#include "pie-relocs.h"
#include "parasite-blob.h"
#include "sigframe.h"
#include "log.h"
#include "infect.h"
#include "infect-priv.h"

/* XXX will be removed soon */
extern int parasite_wait_ack(int sockfd, unsigned int cmd, struct ctl_msg *m);

#define PTRACE_EVENT_STOP	128

#ifndef SECCOMP_MODE_DISABLED
#define SECCOMP_MODE_DISABLED 0
#endif

#ifndef PTRACE_O_SUSPEND_SECCOMP
# define PTRACE_O_SUSPEND_SECCOMP (1 << 21)
#endif

#define SI_EVENT(_si_code)	(((_si_code) & 0xFFFF) >> 8)

int compel_stop_task(int pid)
{
	int ret;

	ret = ptrace(PTRACE_SEIZE, pid, NULL, 0);
	if (ret) {
		/*
		 * ptrace API doesn't allow to distinguish
		 * attaching to zombie from other errors.
		 * All errors will be handled in compel_wait_task().
		 */
		pr_warn("Unable to interrupt task: %d (%s)\n", pid, strerror(errno));
		return ret;
	}

	/*
	 * If we SEIZE-d the task stop it before going
	 * and reading its stat from proc. Otherwise task
	 * may die _while_ we're doing it and we'll have
	 * inconsistent seize/state pair.
	 *
	 * If task dies after we seize it but before we
	 * do this interrupt, we'll notice it via proc.
	 */
	ret = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
	if (ret < 0) {
		pr_warn("SEIZE %d: can't interrupt task: %s", pid, strerror(errno));
		if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
			pr_perror("Unable to detach from %d", pid);
	}

	return ret;
}

static int skip_sigstop(int pid, int nr_signals)
{
	int i, status, ret;

	/*
	 * 1) SIGSTOP is queued, but isn't handled yet:
	 * SGISTOP can't be blocked, so we need to wait when the kernel
	 * handles this signal.
	 *
	 * Otherwise the process will be stopped immediately after
	 * starting it.
	 *
	 * 2) A seized task was stopped:
	 * PTRACE_SEIZE doesn't affect signal or group stop state.
	 * Currently ptrace reported that task is in stopped state.
	 * We need to start task again, and it will be trapped
	 * immediately, because we sent PTRACE_INTERRUPT to it.
	 */
	for (i = 0; i < nr_signals; i++) {
		ret = ptrace(PTRACE_CONT, pid, 0, 0);
		if (ret) {
			pr_perror("Unable to start process");
			return -1;
		}

		ret = wait4(pid, &status, __WALL, NULL);
		if (ret < 0) {
			pr_perror("SEIZE %d: can't wait task", pid);
			return -1;
		}

		if (!WIFSTOPPED(status)) {
			pr_err("SEIZE %d: task not stopped after seize\n", pid);
			return -1;
		}
	}
	return 0;
}

static int do_suspend_seccomp(pid_t pid)
{
	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_SUSPEND_SECCOMP) < 0) {
		pr_perror("suspending seccomp failed");
		return -1;
	}

	return 0;
}

/*
 * This routine seizes task putting it into a special
 * state where we can manipulate the task via ptrace
 * interface, and finally we can detach ptrace out of
 * of it so the task would not know if it was saddled
 * up with someone else.
 */
int compel_wait_task(int pid, int ppid,
		int (*get_status)(int pid, struct seize_task_status *),
		struct seize_task_status *ss)
{
	siginfo_t si;
	int status, nr_sigstop;
	int ret = 0, ret2, wait_errno = 0;

	/*
	 * It's ugly, but the ptrace API doesn't allow to distinguish
	 * attaching to zombie from other errors. Thus we have to parse
	 * the target's /proc/pid/stat. Sad, but parse whatever else
	 * we might need at that early point.
	 */

try_again:

	ret = wait4(pid, &status, __WALL, NULL);
	if (ret < 0) {
		/*
		 * wait4() can expectedly fail only in a first time
		 * if a task is zombie. If we are here from try_again,
		 * this means that we are tracing this task.
		 *
		 * So here we can be only once in this function.
		 */
		wait_errno = errno;
	}

	ret2 = get_status(pid, ss);
	if (ret2)
		goto err;

	if (ret < 0 || WIFEXITED(status) || WIFSIGNALED(status)) {
		if (ss->state != 'Z') {
			if (pid == getpid())
				pr_err("The criu itself is within dumped tree.\n");
			else
				pr_err("Unseizable non-zombie %d found, state %c, err %d/%d\n",
						pid, ss->state, ret, wait_errno);
			return -1;
		}

		if (ret < 0)
			return TASK_ZOMBIE;
		else
			return TASK_DEAD;
	}

	if ((ppid != -1) && (ss->ppid != ppid)) {
		pr_err("Task pid reused while suspending (%d: %d -> %d)\n",
				pid, ppid, ss->ppid);
		goto err;
	}

	if (!WIFSTOPPED(status)) {
		pr_err("SEIZE %d: task not stopped after seize\n", pid);
		goto err;
	}

	ret = ptrace(PTRACE_GETSIGINFO, pid, NULL, &si);
	if (ret < 0) {
		pr_perror("SEIZE %d: can't read signfo", pid);
		goto err;
	}

	if (SI_EVENT(si.si_code) != PTRACE_EVENT_STOP) {
		/*
		 * Kernel notifies us about the task being seized received some
		 * event other than the STOP, i.e. -- a signal. Let the task
		 * handle one and repeat.
		 */

		if (ptrace(PTRACE_CONT, pid, NULL,
					(void *)(unsigned long)si.si_signo)) {
			pr_perror("Can't continue signal handling, aborting");
			goto err;
		}

		ret = 0;
		goto try_again;
	}

	if (ss->seccomp_mode != SECCOMP_MODE_DISABLED && do_suspend_seccomp(pid) < 0)
		goto err;

	nr_sigstop = 0;
	if (ss->sigpnd & (1 << (SIGSTOP - 1)))
		nr_sigstop++;
	if (ss->shdpnd & (1 << (SIGSTOP - 1)))
		nr_sigstop++;
	if (si.si_signo == SIGSTOP)
		nr_sigstop++;

	if (nr_sigstop) {
		if (skip_sigstop(pid, nr_sigstop))
			goto err_stop;

		return TASK_STOPPED;
	}

	if (si.si_signo == SIGTRAP)
		return TASK_ALIVE;
	else {
		pr_err("SEIZE %d: unsupported stop signal %d\n", pid, si.si_signo);
		goto err;
	}

err_stop:
	kill(pid, SIGSTOP);
err:
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
		pr_perror("Unable to detach from %d", pid);
	return -1;
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

static int prepare_tsock(struct parasite_ctl *ctl, pid_t pid,
		struct parasite_init_args *args)
{
	static int ssock = -1;

	pr_info("Putting tsock into pid %d\n", pid);
	args->h_addr_len = gen_parasite_saddr(&args->h_addr, getpid());

	if (ssock == -1) {
		ssock = *ctl->ictx.p_sock;
		if (ssock == -1) {
			pr_err("No socket in ictx\n");
			goto err;
		}

		*ctl->ictx.p_sock = -1;

		if (bind(ssock, (struct sockaddr *)&args->h_addr, args->h_addr_len) < 0) {
			pr_perror("Can't bind socket");
			goto err;
		}

		if (listen(ssock, 1)) {
			pr_perror("Can't listen on transport socket");
			goto err;
		}
	}

	/* Check a case when parasite can't initialize a command socket */
	if (ctl->ictx.flags & INFECT_FAIL_CONNECT)
		args->h_addr_len = gen_parasite_saddr(&args->h_addr, getpid() + 1);

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

static int setup_child_handler(struct parasite_ctl *ctl)
{
	struct sigaction sa = {
		.sa_sigaction	= ctl->ictx.child_handler,
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

int parasite_run(pid_t pid, int cmd, unsigned long ip, void *stack,
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

static int parasite_init_daemon(struct parasite_ctl *ctl)
{
	struct parasite_init_args *args;
	pid_t pid = ctl->rpid;
	user_regs_struct_t regs;
	struct ctl_msg m = { };

	*ctl->addr_cmd = PARASITE_CMD_INIT_DAEMON;

	args = parasite_args(ctl, struct parasite_init_args);

	args->sigframe = (uintptr_t)ctl->rsigframe;
	args->log_level = log_get_loglevel();

	futex_set(&args->daemon_connected, 0);

	if (prepare_tsock(ctl, pid, args))
		goto err;

	/* after this we can catch parasite errors in chld handler */
	if (setup_child_handler(ctl))
		goto err;

	regs = ctl->orig.regs;
	if (parasite_run(pid, PTRACE_CONT, ctl->parasite_ip, ctl->rstack, &regs, &ctl->orig))
		goto err;

	futex_wait_while_eq(&args->daemon_connected, 0);
	if (futex_get(&args->daemon_connected) != 1) {
		errno = -(int)futex_get(&args->daemon_connected);
		pr_perror("Unable to connect a transport socket");
		goto err;
	}

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

static int parasite_start_daemon(struct parasite_ctl *ctl)
{
	pid_t pid = ctl->rpid;
	struct infect_ctx *ictx = &ctl->ictx;

	/*
	 * Get task registers before going daemon, since the
	 * get_task_regs needs to call ptrace on _stopped_ task,
	 * while in daemon it is not such.
	 */

	if (get_task_regs(pid, ctl->orig.regs, ictx->save_regs, ictx->regs_arg)) {
		pr_err("Can't obtain regs for thread %d\n", pid);
		return -1;
	}

	if (ictx->make_sigframe(ictx->regs_arg, ctl->sigframe, ctl->rsigframe, &ctl->orig.sigmask))
		return -1;

	if (parasite_init_daemon(ctl))
		return -1;

	return 0;
}

#define init_parasite_ctl(ctl, blob_type)				\
	do {								\
	memcpy(ctl->local_map, parasite_##blob_type##_blob,		\
		sizeof(parasite_##blob_type##_blob));			\
	ELF_RELOCS_APPLY(parasite_##blob_type,				\
		ctl->local_map, ctl->remote_map);			\
	/* Setup the rest of a control block */				\
	ctl->parasite_ip = (unsigned long)parasite_sym(ctl->remote_map,	\
		blob_type, __export_parasite_head_start);		\
	ctl->addr_cmd    = parasite_sym(ctl->local_map, blob_type,	\
		__export_parasite_cmd);					\
	ctl->addr_args   = parasite_sym(ctl->local_map, blob_type,	\
		__export_parasite_args);				\
	} while (0)

int compel_infect(struct parasite_ctl *ctl, unsigned long nr_threads, unsigned long args_size)
{
	int ret;
	unsigned long p, map_exchange_size, parasite_size = 0;

	if (!arch_can_dump_task(ctl))
		goto err;

	/*
	 * Inject a parasite engine. Ie allocate memory inside alien
	 * space and copy engine code there. Then re-map the engine
	 * locally, so we will get an easy way to access engine memory
	 * without using ptrace at all.
	 */

	if (seized_native(ctl))
		parasite_size = pie_size(parasite_native);
#ifdef CONFIG_COMPAT
	else
		parasite_size = pie_size(parasite_compat);
#endif

	ctl->args_size = round_up(args_size, PAGE_SIZE);
	parasite_size += ctl->args_size;

	map_exchange_size = parasite_size;
	map_exchange_size += RESTORE_STACK_SIGFRAME + PARASITE_STACK_SIZE;
	if (nr_threads > 1)
		map_exchange_size += PARASITE_STACK_SIZE;

	ret = parasite_map_exchange(ctl, map_exchange_size);
	if (ret)
		goto err;

	pr_info("Putting parasite blob into %p->%p\n", ctl->local_map, ctl->remote_map);

	if (seized_native(ctl))
		init_parasite_ctl(ctl, native);
#ifdef CONFIG_COMPAT
	else
		init_parasite_ctl(ctl, compat);
#endif

	p = parasite_size;

	ctl->rsigframe	= ctl->remote_map + p;
	ctl->sigframe	= ctl->local_map  + p;

	p += RESTORE_STACK_SIGFRAME;
	p += PARASITE_STACK_SIZE;
	ctl->rstack = ctl->remote_map + p;

	if (nr_threads > 1) {
		p += PARASITE_STACK_SIZE;
		ctl->r_thread_stack = ctl->remote_map + p;
	}

	if (parasite_start_daemon(ctl))
		goto err;

	return 0;

err:
	return -1;
}

