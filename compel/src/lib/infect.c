#include <inttypes.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>
#include <linux/seccomp.h>

#include "log.h"
#include "common/bug.h"
#include "common/xmalloc.h"
#include "common/lock.h"
#include "common/page.h"

#include <compel/plugins/std/syscall-codes.h>
#include <compel/plugins/std/asm/syscall-types.h>
#include "uapi/compel/plugins/std/syscall.h"
#include "asm/infect-types.h"
#include "asm/sigframe.h"
#include "infect.h"
#include "ptrace.h"
#include "infect-rpc.h"
#include "infect-priv.h"
#include "infect-util.h"
#include "rpc-pie-priv.h"
#include "infect-util.h"

#define __sys(foo)     foo
#define __sys_err(ret) (-errno)

#include "common/scm.h"
#include "common/scm-code.c"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX (sizeof(struct sockaddr_un) - (size_t)((struct sockaddr_un *)0)->sun_path)
#endif

#define PARASITE_STACK_SIZE (16 << 10)

#ifndef SECCOMP_MODE_DISABLED
#define SECCOMP_MODE_DISABLED 0
#endif

static int prepare_thread(int pid, struct thread_ctx *ctx);

static inline void close_safe(int *pfd)
{
	if (*pfd > -1) {
		close(*pfd);
		*pfd = -1;
	}
}

static int parse_pid_status(int pid, struct seize_task_status *ss, void *data)
{
	char aux[128];
	FILE *f;

	sprintf(aux, "/proc/%d/status", pid);
	f = fopen(aux, "r");
	if (!f)
		return -1;

	ss->ppid = -1; /* Not needed at this point */
	ss->seccomp_mode = SECCOMP_MODE_DISABLED;

	while (fgets(aux, sizeof(aux), f)) {
		if (!strncmp(aux, "State:", 6)) {
			ss->state = aux[7];
			continue;
		}

		if (!strncmp(aux, "Seccomp:", 8)) {
			if (sscanf(aux + 9, "%d", &ss->seccomp_mode) != 1)
				goto err_parse;

			continue;
		}

		if (!strncmp(aux, "ShdPnd:", 7)) {
			if (sscanf(aux + 7, "%llx", &ss->shdpnd) != 1)
				goto err_parse;

			continue;
		}
		if (!strncmp(aux, "SigPnd:", 7)) {
			if (sscanf(aux + 7, "%llx", &ss->sigpnd) != 1)
				goto err_parse;

			continue;
		}
	}

	fclose(f);
	return 0;

err_parse:
	fclose(f);
	return -1;
}

int compel_stop_task(int pid)
{
	int ret;
	struct seize_task_status ss = {};

	ret = compel_interrupt_task(pid);
	if (ret == 0)
		ret = compel_wait_task(pid, -1, parse_pid_status, NULL, &ss, NULL);
	return ret;
}

int compel_interrupt_task(int pid)
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
		pr_warn("SEIZE %d: can't interrupt task: %s\n", pid, strerror(errno));
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

/*
 * This routine seizes task putting it into a special
 * state where we can manipulate the task via ptrace
 * interface, and finally we can detach ptrace out of
 * of it so the task would not know if it was saddled
 * up with someone else.
 */
int compel_wait_task(int pid, int ppid, int (*get_status)(int pid, struct seize_task_status *, void *),
		     void (*free_status)(int pid, struct seize_task_status *, void *), struct seize_task_status *ss,
		     void *data)
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

	ret2 = get_status(pid, ss, data);
	if (ret2)
		goto err;

	if (ret < 0 || WIFEXITED(status) || WIFSIGNALED(status)) {
		if (ss->state != 'Z') {
			if (pid == getpid())
				pr_err("The criu itself is within dumped tree.\n");
			else
				pr_err("Unseizable non-zombie %d found, state %c, err %d/%d\n", pid, ss->state, ret,
				       wait_errno);
			return -1;
		}

		if (ret < 0)
			return COMPEL_TASK_ZOMBIE;
		else
			return COMPEL_TASK_DEAD;
	}

	if ((ppid != -1) && (ss->ppid != ppid)) {
		pr_err("Task pid reused while suspending (%d: %d -> %d)\n", pid, ppid, ss->ppid);
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

	if (PTRACE_SI_EVENT(si.si_code) != PTRACE_EVENT_STOP) {
		/*
		 * Kernel notifies us about the task being seized received some
		 * event other than the STOP, i.e. -- a signal. Let the task
		 * handle one and repeat.
		 */

		if (ptrace(PTRACE_CONT, pid, NULL, (void *)(unsigned long)si.si_signo)) {
			pr_perror("Can't continue signal handling, aborting");
			goto err;
		}

		if (free_status)
			free_status(pid, ss, data);
		goto try_again;
	}

	if (ss->seccomp_mode != SECCOMP_MODE_DISABLED && ptrace_suspend_seccomp(pid) < 0)
		goto err;

	/*
	 * FIXME(issues/1429): parasite code contains instructions that trigger
	 * SIGTRAP to stop at certain points. In such cases, the kernel sends a
	 * force SIGTRAP that can't be ignored and if it is blocked, the kernel
	 * resets its signal handler to a default one and unblocks it. It means
	 * that if we want to save the origin signal handler, we need to run a
	 * parasite code with the unblocked SIGTRAP.
	 */
	if ((ss->sigpnd | ss->shdpnd) & (1 << (SIGTRAP - 1))) {
		pr_err("Can't dump the %d thread with a pending SIGTRAP.\n", pid);
		goto err;
	}

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

		return COMPEL_TASK_STOPPED;
	}

	if (si.si_signo == SIGTRAP)
		return COMPEL_TASK_ALIVE;
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

int compel_resume_task(pid_t pid, int orig_st, int st)
{
	int ret = 0;

	pr_debug("\tUnseizing %d into %d\n", pid, st);

	if (st == COMPEL_TASK_DEAD) {
		kill(pid, SIGKILL);
		return 0;
	} else if (st == COMPEL_TASK_STOPPED) {
		/*
		 * Task might have had STOP in queue. We detected such
		 * guy as COMPEL_TASK_STOPPED, but cleared signal to run
		 * the parasite code. Thus after detach the task will become
		 * running. That said -- STOP everyone regardless of
		 * the initial state.
		 */
		kill(pid, SIGSTOP);
	} else if (st == COMPEL_TASK_ALIVE) {
		/*
		 * Same as in the comment above -- there might be a
		 * task with STOP in queue that would get lost after
		 * detach, so stop it again.
		 */
		if (orig_st == COMPEL_TASK_STOPPED)
			kill(pid, SIGSTOP);
	} else {
		pr_err("Unknown final state %d\n", st);
		ret = -1;
	}

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		pr_perror("Unable to detach from %d", pid);
		return -1;
	}

	return ret;
}

static int gen_parasite_saddr(struct sockaddr_un *saddr, int key)
{
	int sun_len;

	saddr->sun_family = AF_UNIX;
	snprintf(saddr->sun_path, UNIX_PATH_MAX, "X/crtools-pr-%d-%" PRIx64, key, compel_run_id);

	sun_len = SUN_LEN(saddr);
	*saddr->sun_path = '\0';

	return sun_len;
}

static int prepare_tsock(struct parasite_ctl *ctl, pid_t pid, struct parasite_init_args *args)
{
	int ssock = -1;
	socklen_t sk_len;
	struct sockaddr_un addr;

	pr_info("Putting tsock into pid %d\n", pid);
	args->h_addr_len = gen_parasite_saddr(&args->h_addr, getpid());

	ssock = ctl->ictx.sock;
	sk_len = sizeof(addr);

	if (ssock == -1) {
		pr_err("No socket in ictx\n");
		goto err;
	}

	if (getsockname(ssock, (struct sockaddr *)&addr, &sk_len) < 0) {
		pr_perror("Unable to get name for a socket");
		return -1;
	}

	if (sk_len == sizeof(addr.sun_family)) {
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
		.sa_sigaction = ctl->ictx.child_handler,
		.sa_flags = SA_SIGINFO | SA_RESTART,
	};

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGCHLD);
	if (sigaction(SIGCHLD, &sa, NULL)) {
		pr_perror("Unable to setup SIGCHLD handler");
		return -1;
	}

	return 0;
}

static int restore_child_handler(struct parasite_ctl *ctl)
{
	if (sigaction(SIGCHLD, &ctl->ictx.orig_handler, NULL)) {
		pr_perror("Unable to setup SIGCHLD handler");
		return -1;
	}

	return 0;
}

static int parasite_run(pid_t pid, int cmd, unsigned long ip, void *stack, user_regs_struct_t *regs,
			struct thread_ctx *octx)
{
	k_rtsigset_t block;

	ksigfillset(&block);
	/*
	 * FIXME(issues/1429): SIGTRAP can't be blocked, otherwise its handler
	 * will be reset to the default one.
	 */
	ksigdelset(&block, SIGTRAP);
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

static int restore_thread_ctx(int pid, struct thread_ctx *ctx, bool restore_ext_regs)
{
	int ret = 0;

	if (ptrace_set_regs(pid, &ctx->regs)) {
		pr_perror("Can't restore registers (pid: %d)", pid);
		ret = -1;
	}

	if (restore_ext_regs && compel_set_task_ext_regs(pid, &ctx->ext_regs))
		ret = -1;

	if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(k_rtsigset_t), &ctx->sigmask)) {
		pr_perror("Can't block signals");
		ret = -1;
	}

	return ret;
}

/* we run at @regs->ip */
static int parasite_trap(struct parasite_ctl *ctl, pid_t pid, user_regs_struct_t *regs, struct thread_ctx *octx,
			 bool may_use_extended_regs)
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
		pr_debug("** delivering signal %d si_code=%d\n", siginfo.si_signo, siginfo.si_code);

		pr_err("Unexpected %d task interruption, aborting\n", pid);
		goto err;
	}

	/*
	 * We've reached this point if int3 is triggered inside our
	 * parasite code. So we're done.
	 */
	ret = 0;
err:
	if (restore_thread_ctx(pid, octx, may_use_extended_regs))
		ret = -1;

	return ret;
}

int compel_execute_syscall(struct parasite_ctl *ctl, user_regs_struct_t *regs, const char *code_syscall)
{
	pid_t pid = ctl->rpid;
	int err;
	uint8_t code_orig[BUILTIN_SYSCALL_SIZE];

	/*
	 * Inject syscall instruction and remember original code,
	 * we will need it to restore original program content.
	 */
	memcpy(code_orig, code_syscall, sizeof(code_orig));
	if (ptrace_swap_area(pid, (void *)ctl->ictx.syscall_ip, (void *)code_orig, sizeof(code_orig))) {
		pr_err("Can't inject syscall blob (pid: %d)\n", pid);
		return -1;
	}

	err = parasite_run(pid, PTRACE_CONT, ctl->ictx.syscall_ip, 0, regs, &ctl->orig);
	if (!err)
		err = parasite_trap(ctl, pid, regs, &ctl->orig, false);

	if (ptrace_poke_area(pid, (void *)code_orig, (void *)ctl->ictx.syscall_ip, sizeof(code_orig))) {
		pr_err("Can't restore syscall blob (pid: %d)\n", ctl->rpid);
		err = -1;
	}

	return err;
}

int compel_run_at(struct parasite_ctl *ctl, unsigned long ip, user_regs_struct_t *ret_regs)
{
	user_regs_struct_t regs = ctl->orig.regs;
	int ret;

	ret = parasite_run(ctl->rpid, PTRACE_CONT, ip, 0, &regs, &ctl->orig);
	if (!ret)
		ret = parasite_trap(ctl, ctl->rpid, ret_regs ? ret_regs : &regs, &ctl->orig, false);
	return ret;
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
	struct ctl_msg m = {};

	*ctl->cmd = PARASITE_CMD_INIT_DAEMON;

	args = compel_parasite_args(ctl, struct parasite_init_args);

	args->sigframe = (uintptr_t)ctl->rsigframe;
	args->log_level = compel_log_get_loglevel();
#ifdef ARCH_HAS_LONG_PAGES
	args->page_size = PAGE_SIZE;
#endif

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

	if (compel_util_send_fd(ctl, ctl->ictx.log_fd))
		goto err;

	pr_info("Wait for parasite being daemonized...\n");

	if (parasite_wait_ack(ctl->tsock, PARASITE_CMD_INIT_DAEMON, &m)) {
		pr_err("Can't switch parasite %d to daemon mode %d\n", pid, m.err);
		goto err;
	}

	ctl->sigreturn_addr = (void *)(uintptr_t)args->sigreturn_addr;
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
	 * compel_get_task_regs() needs to call ptrace on _stopped_ task,
	 * while in daemon it is not such.
	 */

	if (compel_get_task_regs(pid, &ctl->orig.regs, NULL, ictx->save_regs, ictx->regs_arg, ictx->flags)) {
		pr_err("Can't obtain regs for thread %d\n", pid);
		return -1;
	}

	if (__compel_arch_fetch_thread_area(pid, &ctl->orig)) {
		pr_err("Can't get thread area of %d\n", pid);
		return -1;
	}

	if (ictx->make_sigframe(ictx->regs_arg, ctl->sigframe, ctl->rsigframe, &ctl->orig.sigmask))
		return -1;

	if (parasite_init_daemon(ctl))
		return -1;

	return 0;
}

static int parasite_mmap_exchange(struct parasite_ctl *ctl, unsigned long size, int remote_prot)
{
	int fd;

	ctl->remote_map = remote_mmap(ctl, NULL, size, remote_prot, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (!ctl->remote_map) {
		pr_err("Can't allocate memory for parasite blob (pid: %d)\n", ctl->rpid);
		return -1;
	}

	ctl->map_length = round_up(size, page_size());

	fd = ctl->ictx.open_proc(ctl->rpid, O_RDWR, "map_files/%lx-%lx", (long)ctl->remote_map,
				 (long)ctl->remote_map + ctl->map_length);
	if (fd < 0)
		return -1;

	ctl->local_map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0);
	close(fd);

	if (ctl->local_map == MAP_FAILED) {
		ctl->local_map = NULL;
		pr_perror("Can't map remote parasite map");
		return -1;
	}

	return 0;
}

static void parasite_memfd_close(struct parasite_ctl *ctl, int fd)
{
	bool compat = !compel_mode_native(ctl);
	long ret;
	int err;

	err = compel_syscall(ctl, __NR(close, compat), &ret, fd, 0, 0, 0, 0, 0);
	if (err || ret)
		pr_err("Can't close memfd\n");
}

static int parasite_memfd_exchange(struct parasite_ctl *ctl, unsigned long size, int remote_prot)
{
	void *where = (void *)ctl->ictx.syscall_ip + BUILTIN_SYSCALL_SIZE;
	bool compat_task = !compel_mode_native(ctl);
	uint8_t orig_code[MEMFD_FNAME_SZ] = MEMFD_FNAME;
	pid_t pid = ctl->rpid;
	long sret = -ENOSYS;
	int ret, fd, lfd;

	if (ctl->ictx.flags & INFECT_NO_MEMFD)
		return 1;

	BUILD_BUG_ON(sizeof(orig_code) < sizeof(long));

	if (ptrace_swap_area(pid, where, (void *)orig_code, sizeof(orig_code))) {
		pr_err("Can't inject memfd args (pid: %d)\n", pid);
		return -1;
	}

	ret = compel_syscall(ctl, __NR(memfd_create, compat_task), &sret, (unsigned long)where, 0, 0, 0, 0, 0);

	if (ptrace_poke_area(pid, orig_code, where, sizeof(orig_code))) {
		fd = (int)sret;
		if (fd >= 0)
			parasite_memfd_close(ctl, fd);
		pr_err("Can't restore memfd args (pid: %d)\n", pid);
		return -1;
	}

	if (ret < 0)
		return ret;

	fd = (int)sret;
	if (fd == -ENOSYS)
		return 1;
	if (fd < 0) {
		errno = -fd;
		pr_perror("Can't create memfd in victim");
		return fd;
	}

	ctl->map_length = round_up(size, page_size());
	lfd = ctl->ictx.open_proc(ctl->rpid, O_RDWR, "fd/%d", fd);
	if (lfd < 0)
		goto err_cure;

	if (ftruncate(lfd, ctl->map_length) < 0) {
		pr_perror("Fail to truncate memfd for parasite");
		goto err_cure;
	}

	ctl->remote_map = remote_mmap(ctl, NULL, size, remote_prot, MAP_FILE | MAP_SHARED, fd, 0);
	if (!ctl->remote_map) {
		pr_err("Can't rmap memfd for parasite blob\n");
		goto err_curef;
	}

	ctl->local_map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, lfd, 0);
	if (ctl->local_map == MAP_FAILED) {
		ctl->local_map = NULL;
		pr_perror("Can't lmap memfd for parasite blob");
		goto err_curef;
	}

	parasite_memfd_close(ctl, fd);
	close(lfd);

	pr_info("Set up parasite blob using memfd\n");
	return 0;

err_curef:
	close(lfd);
err_cure:
	parasite_memfd_close(ctl, fd);
	return -1;
}

void compel_relocs_apply(void *mem, void *vbase, struct parasite_blob_desc *pbd)
{
	compel_reloc_t *elf_relocs = pbd->hdr.relocs;
	size_t nr_relocs = pbd->hdr.nr_relocs;

	size_t i, j;
	void **got = mem + pbd->hdr.got_off;

	/*
	 * parasite_service() reads the value of __export_parasite_service_args_ptr.
	 * The reason it is set here is that semantically, we are doing a symbol
	 * resolution on parasite_service_args, and it turns out to be relocatable.
	 */
	*(void **)(mem + pbd->hdr.args_ptr_off) = vbase + pbd->hdr.args_off;

#ifdef CONFIG_MIPS
	compel_relocs_apply_mips(mem, vbase, pbd);
#else
	for (i = 0, j = 0; i < nr_relocs; i++) {
		if (elf_relocs[i].type & COMPEL_TYPE_LONG) {
			long *where = mem + elf_relocs[i].offset;

			if (elf_relocs[i].type & COMPEL_TYPE_GOTPCREL) {
				int *value = (int *)where;
				int rel;

				got[j] = vbase + elf_relocs[i].value;
				rel = (unsigned)((void *)&got[j] - (void *)mem) - elf_relocs[i].offset +
				      elf_relocs[i].addend;

				*value = rel;
				j++;
			} else
				*where = elf_relocs[i].value + elf_relocs[i].addend + (unsigned long)vbase;
		} else if (elf_relocs[i].type & COMPEL_TYPE_INT) {
			int *where = (mem + elf_relocs[i].offset);
			*where = elf_relocs[i].value + elf_relocs[i].addend + (unsigned long)vbase;
		} else
			BUG();
	}
#endif
}

long remote_mprotect(struct parasite_ctl *ctl, void *addr, size_t len, int prot)
{
	long ret;
	int err;
	bool compat_task = !user_regs_native(&ctl->orig.regs);

	err = compel_syscall(ctl, __NR(mprotect, compat_task), &ret, (unsigned long)addr, len, prot, 0, 0, 0);
	if (err < 0) {
		pr_err("compel_syscall for mprotect failed\n");
		return -1;
	}
	return ret;
}

static int compel_map_exchange(struct parasite_ctl *ctl, unsigned long size)
{
	int ret, remote_prot;

	if (ctl->pblob.hdr.data_off)
		remote_prot = PROT_READ | PROT_EXEC;
	else
		remote_prot = PROT_READ | PROT_WRITE | PROT_EXEC;

	ret = parasite_memfd_exchange(ctl, size, remote_prot);
	if (ret == 1) {
		pr_info("MemFD parasite doesn't work, goto legacy mmap\n");
		ret = parasite_mmap_exchange(ctl, size, remote_prot);
		if (ret)
			return ret;
	}

	if (!ctl->pblob.hdr.data_off)
		return 0;

	ret = remote_mprotect(ctl, ctl->remote_map + ctl->pblob.hdr.data_off, size - ctl->pblob.hdr.data_off,
			      PROT_READ | PROT_WRITE);
	if (ret)
		pr_err("remote_mprotect failed\n");

	return ret;
}

int compel_infect(struct parasite_ctl *ctl, unsigned long nr_threads, unsigned long args_size)
{
	int ret;
	unsigned long p, map_exchange_size, parasite_size = 0;

	if (ctl->pblob.parasite_type != COMPEL_BLOB_CHEADER)
		goto err;

	if (ctl->ictx.log_fd < 0)
		goto err;

	if (!arch_can_dump_task(ctl))
		goto err;

	/*
	 * Inject a parasite engine. Ie allocate memory inside alien
	 * space and copy engine code there. Then re-map the engine
	 * locally, so we will get an easy way to access engine memory
	 * without using ptrace at all.
	 */

	/*
	 * The parasite memory layout is the following:
	 * Low address start first.
	 * The number in parenthesis denotes the size of the section.
	 * The arrow on the right shows the different variables that
	 * corresponds to a given offset.
	 * +------------------------------------------------------+ <--- 0
	 * |   Parasite blob (sizeof(parasite_blob))              |
	 * +------------------------------------------------------+ <--- hdr.bsize
	 *                         align 8
	 * +------------------------------------------------------+ <--- hdr.got_off
	 * |   GOT Table (nr_gotpcrel * sizeof(long))             |
	 * +------------------------------------------------------+ <--- hdr.args_off
	 * |   Args area (args_size)                              |
	 * +------------------------------------------------------+
	 *                         align 64
	 * +------------------------------------------------------+ <--- ctl->rsigframe
	 * |   sigframe (RESTORE_STACK_SIGFRAME)                  |      ctl->sigframe
	 * +------------------------------------------------------+
	 * |   main stack (PARASITE_STACK_SIZE)                   |
	 * +------------------------------------------------------+ <--- ctl->rstack
	 * |   compel_run_in_thread stack (PARASITE_STACK_SIZE)   |
	 * +------------------------------------------------------+ <--- ctl->r_thread_stack
	 *                                                               map_exchange_size
	 */
	parasite_size = ctl->pblob.hdr.args_off;

	ctl->args_size = args_size;
	parasite_size += ctl->args_size;

	/* RESTORE_STACK_SIGFRAME needs a 64 bytes alignment */
	parasite_size = round_up(parasite_size, 64);

	map_exchange_size = parasite_size;
	map_exchange_size += RESTORE_STACK_SIGFRAME + PARASITE_STACK_SIZE;
	if (nr_threads > 1)
		map_exchange_size += PARASITE_STACK_SIZE;

	ret = compel_map_exchange(ctl, map_exchange_size);
	if (ret)
		goto err;

	pr_info("Putting parasite blob into %p->%p\n", ctl->local_map, ctl->remote_map);

	ctl->parasite_ip = (unsigned long)(ctl->remote_map + ctl->pblob.hdr.parasite_ip_off);
	ctl->cmd = ctl->local_map + ctl->pblob.hdr.cmd_off;
	ctl->args = ctl->local_map + ctl->pblob.hdr.args_off;

	/*
	 * args must be 4 bytes aligned as we use futexes() on them. It is
	 * already the case, as args follows the GOT table, which is 8 bytes
	 * aligned.
	 */
	if ((unsigned long)ctl->args & (4 - 1)) {
		pr_err("BUG: args are not 4 bytes aligned: %p\n", ctl->args);
		goto err;
	}

	memcpy(ctl->local_map, ctl->pblob.hdr.mem, ctl->pblob.hdr.bsize);
	compel_relocs_apply(ctl->local_map, ctl->remote_map, &ctl->pblob);

	p = parasite_size;

	ctl->rsigframe = ctl->remote_map + p;
	ctl->sigframe = ctl->local_map + p;

	p += RESTORE_STACK_SIGFRAME;
	p += PARASITE_STACK_SIZE;
	ctl->rstack = ctl->remote_map + p;

	/*
	 * x86-64 ABI requires a 16 bytes aligned stack.
	 * It is already the case as RESTORE_STACK_SIGFRAME is a multiple of
	 * 64, and PARASITE_STACK_SIZE is 0x4000.
	 */
	if ((unsigned long)ctl->rstack & (16 - 1)) {
		pr_err("BUG: stack is not 16 bytes aligned: %p\n", ctl->rstack);
		goto err;
	}

	if (nr_threads > 1) {
		p += PARASITE_STACK_SIZE;
		ctl->r_thread_stack = ctl->remote_map + p;
	}

	ret = arch_fetch_sas(ctl, ctl->rsigframe);
	if (ret) {
		pr_err("Can't fetch sigaltstack for task %d (ret %d)\n", ctl->rpid, ret);
		goto err;
	}

	if (parasite_start_daemon(ctl))
		goto err;

	return 0;

err:
	return -1;
}

struct parasite_thread_ctl *compel_prepare_thread(struct parasite_ctl *ctl, int pid)
{
	struct parasite_thread_ctl *tctl;

	tctl = xmalloc(sizeof(*tctl));
	if (tctl) {
		if (prepare_thread(pid, &tctl->th)) {
			xfree(tctl);
			tctl = NULL;
		} else {
			tctl->tid = pid;
			tctl->ctl = ctl;
		}
	}

	return tctl;
}

static int prepare_thread(int pid, struct thread_ctx *ctx)
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

void compel_release_thread(struct parasite_thread_ctl *tctl)
{
	/*
	 * No stuff to cure in thread here, all routines leave the
	 * guy intact (for now)
	 */
	xfree(tctl);
}

struct parasite_ctl *compel_prepare_noctx(int pid)
{
	struct parasite_ctl *ctl = NULL;

	/*
	 * Control block early setup.
	 */
	ctl = xzalloc(sizeof(*ctl));
	if (!ctl) {
		pr_err("Parasite control block allocation failed (pid: %d)\n", pid);
		goto err;
	}

	ctl->tsock = -1;
	ctl->ictx.log_fd = -1;

	if (prepare_thread(pid, &ctl->orig))
		goto err;

	ctl->rpid = pid;

	BUILD_BUG_ON(PARASITE_START_AREA_MIN < BUILTIN_SYSCALL_SIZE + MEMFD_FNAME_SZ);

	return ctl;

err:
	xfree(ctl);
	return NULL;
}

/*
 * Find first executable VMA that would fit the initial
 * syscall injection.
 */
static unsigned long find_executable_area(int pid)
{
	char aux[128];
	FILE *f;
	unsigned long ret = (unsigned long)MAP_FAILED;

	sprintf(aux, "/proc/%d/maps", pid);
	f = fopen(aux, "r");
	if (!f)
		goto out;

	while (fgets(aux, sizeof(aux), f)) {
		unsigned long start, end;
		char *f;

		start = strtoul(aux, &f, 16);
		end = strtoul(f + 1, &f, 16);

		/* f now points at " rwx" (yes, with space) part */
		if (f[3] == 'x') {
			BUG_ON(end - start < PARASITE_START_AREA_MIN);
			ret = start;
			break;
		}
	}

	fclose(f);
out:
	return ret;
}

/*
 * This routine is to create PF_UNIX/SOCK_SEQPACKET socket
 * in the target net namespace
 */
static int make_sock_for(int pid)
{
	int ret, mfd, fd, sk = -1;
	char p[32];

	pr_debug("Preparing seqsk for %d\n", pid);

	sprintf(p, "/proc/%d/ns/net", pid);
	fd = open(p, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %p", p);
		goto out;
	}

	mfd = open("/proc/self/ns/net", O_RDONLY);
	if (mfd < 0) {
		pr_perror("Can't open self netns");
		goto out_c;
	}

	if (setns(fd, CLONE_NEWNET)) {
		pr_perror("Can't setup target netns");
		goto out_cm;
	}

	sk = socket(PF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
	if (sk < 0)
		pr_perror("Can't create seqsk");

	ret = setns(mfd, CLONE_NEWNET);
	if (ret) {
		pr_perror("Can't restore former netns");
		if (sk >= 0)
			close(sk);
		sk = -1;
	}
out_cm:
	close(mfd);
out_c:
	close(fd);
out:
	return sk;
}

static int simple_open_proc(int pid, int mode, const char *fmt, ...)
{
	int l;
	char path[128];
	va_list args;

	l = sprintf(path, "/proc/%d/", pid);

	va_start(args, fmt);
	vsnprintf(path + l, sizeof(path) - l, fmt, args);
	va_end(args);

	return open(path, mode);
}

static void handle_sigchld(int signal, siginfo_t *siginfo, void *data)
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

	/* FIXME Should we exit? */
	/* exit(1); */
}

struct plain_regs_struct {
	user_regs_struct_t regs;
	user_fpregs_struct_t fpregs;
};

static int save_regs_plain(void *to, user_regs_struct_t *r, user_fpregs_struct_t *f)
{
	struct plain_regs_struct *prs = to;

	prs->regs = *r;
	prs->fpregs = *f;

	return 0;
}

static int make_sigframe_plain(void *from, struct rt_sigframe *f, struct rt_sigframe *rtf, k_rtsigset_t *b)
{
	struct plain_regs_struct *prs = from;

	/*
	 * Make sure it's zeroified.
	 */
	memset(f, 0, sizeof(*f));

	if (sigreturn_prep_regs_plain(f, &prs->regs, &prs->fpregs))
		return -1;

	if (b)
		rt_sigframe_copy_sigset(f, b);

	if (RT_SIGFRAME_HAS_FPU(f)) {
		if (sigreturn_prep_fpu_frame_plain(f, rtf))
			return -1;
	}

	/*
	 * FIXME What about sas?
	 * setup_sas(sigframe, core->thread_core->sas);
	 */

	return 0;
}

struct parasite_ctl *compel_prepare(int pid)
{
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;

	ctl = compel_prepare_noctx(pid);
	if (ctl == NULL)
		goto out;

	ictx = &ctl->ictx;
	ictx->task_size = compel_task_size();
	ictx->open_proc = simple_open_proc;
	ictx->syscall_ip = find_executable_area(pid);
	ictx->child_handler = handle_sigchld;
	sigaction(SIGCHLD, NULL, &ictx->orig_handler);

	ictx->save_regs = save_regs_plain;
	ictx->make_sigframe = make_sigframe_plain;
	ictx->regs_arg = xmalloc(sizeof(struct plain_regs_struct));
	if (ictx->regs_arg == NULL)
		goto err;

	if (ictx->syscall_ip == (unsigned long)MAP_FAILED)
		goto err;
	ictx->sock = make_sock_for(pid);
	if (ictx->sock < 0)
		goto err;

out:
	return ctl;

err:
	xfree(ictx->regs_arg);
	xfree(ctl);
	ctl = NULL;
	goto out;
}

static bool task_in_parasite(struct parasite_ctl *ctl, user_regs_struct_t *regs)
{
	void *addr = (void *)REG_IP(*regs);
	return addr >= ctl->remote_map && addr < ctl->remote_map + ctl->map_length;
}

static int parasite_fini_seized(struct parasite_ctl *ctl)
{
	pid_t pid = ctl->rpid;
	user_regs_struct_t regs;
	int status, ret = 0;
	enum trace_flags flag;

	/* stop getting chld from parasite -- we're about to step-by-step it */
	if (restore_child_handler(ctl))
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

	ret = compel_rpc_call(PARASITE_CMD_FINI, ctl);
	close_safe(&ctl->tsock);
	if (ret)
		return -1;

	/* Go to sigreturn as closer as we can */
	ret = compel_stop_pie(pid, ctl->sigreturn_addr, &flag, ctl->ictx.flags & INFECT_NO_BREAKPOINTS);
	if (ret < 0)
		return ret;

	if (compel_stop_on_syscall(1, __NR(rt_sigreturn, 0), __NR(rt_sigreturn, 1), flag))
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

int compel_stop_daemon(struct parasite_ctl *ctl)
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

int compel_cure_remote(struct parasite_ctl *ctl)
{
	long ret;
	int err;

	if (compel_stop_daemon(ctl))
		return -1;

	if (!ctl->remote_map)
		return 0;

	err = compel_syscall(ctl, __NR(munmap, !compel_mode_native(ctl)), &ret, (unsigned long)ctl->remote_map,
			     ctl->map_length, 0, 0, 0, 0);
	if (err)
		return err;

	if (ret) {
		pr_err("munmap for remote map %p, %lu returned %lu\n", ctl->remote_map, ctl->map_length, ret);
		return -1;
	}

	return 0;
}

int compel_cure_local(struct parasite_ctl *ctl)
{
	int ret = 0;

	if (ctl->local_map) {
		if (munmap(ctl->local_map, ctl->map_length)) {
			pr_err("munmap failed (pid: %d)\n", ctl->rpid);
			ret = -1;
		}
	}

	free(ctl);
	return ret;
}

int compel_cure(struct parasite_ctl *ctl)
{
	int ret;

	ret = compel_cure_remote(ctl);
	if (!ret)
		ret = compel_cure_local(ctl);

	return ret;
}

void *compel_parasite_args_p(struct parasite_ctl *ctl)
{
	return ctl->args;
}

void *compel_parasite_args_s(struct parasite_ctl *ctl, unsigned long args_size)
{
	BUG_ON(args_size > ctl->args_size);
	return compel_parasite_args_p(ctl);
}

int compel_run_in_thread(struct parasite_thread_ctl *tctl, unsigned int cmd)
{
	int pid = tctl->tid;
	struct parasite_ctl *ctl = tctl->ctl;
	struct thread_ctx *octx = &tctl->th;
	void *stack = ctl->r_thread_stack;
	user_regs_struct_t regs = octx->regs;
	int ret;

	*ctl->cmd = cmd;

	ret = parasite_run(pid, PTRACE_CONT, ctl->parasite_ip, stack, &regs, octx);
	if (ret == 0)
		ret = parasite_trap(ctl, pid, &regs, octx, true);
	if (ret == 0)
		ret = (int)REG_RES(regs);

	if (ret)
		pr_err("Parasite exited with %d\n", ret);

	return ret;
}

/*
 * compel_unmap() is used for unmapping parasite and restorer blobs.
 * A blob can contain code for unmapping itself, so the process is
 * trapped on the exit from the munmap syscall.
 */
int compel_unmap(struct parasite_ctl *ctl, unsigned long addr)
{
	user_regs_struct_t regs = ctl->orig.regs;
	pid_t pid = ctl->rpid;
	int ret = -1;

	ret = parasite_run(pid, PTRACE_SYSCALL, addr, ctl->rstack, &regs, &ctl->orig);
	if (ret)
		goto err;

	ret = compel_stop_on_syscall(1, __NR(munmap, 0), __NR(munmap, 1), TRACE_ENTER);

	/*
	 * Don't touch extended registers here: they were restored
	 * with rt_sigreturn from sigframe.
	 */
	if (restore_thread_ctx(pid, &ctl->orig, false))
		ret = -1;
err:
	return ret;
}

int compel_stop_pie(pid_t pid, void *addr, enum trace_flags *tf, bool no_bp)
{
	int ret;

	if (no_bp) {
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

static bool task_is_trapped(int status, pid_t pid)
{
	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
		return true;

	pr_err("Task %d is in unexpected state: %x\n", pid, status);
	if (WIFEXITED(status))
		pr_err("Task exited with %d\n", WEXITSTATUS(status));
	if (WIFSIGNALED(status))
		pr_err("Task signaled with %d: %s\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
	if (WIFSTOPPED(status))
		pr_err("Task stopped with %d: %s\n", WSTOPSIG(status), strsignal(WSTOPSIG(status)));
	if (WIFCONTINUED(status))
		pr_err("Task continued\n");

	return false;
}

static inline int is_required_syscall(user_regs_struct_t *regs, pid_t pid, const int sys_nr, const int sys_nr_compat)
{
	const char *mode = user_regs_native(regs) ? "native" : "compat";
	int req_sysnr = user_regs_native(regs) ? sys_nr : sys_nr_compat;

	pr_debug("%d (%s) is going to execute the syscall %lu, required is %d\n", pid, mode, REG_SYSCALL_NR(*regs),
		 req_sysnr);

	return (REG_SYSCALL_NR(*regs) == req_sysnr);
}

/*
 * Trap tasks on the exit from the specified syscall
 *
 * tasks - number of processes, which should be trapped
 * sys_nr - the required syscall number
 * sys_nr_compat - the required compatible syscall number
 */
int compel_stop_on_syscall(int tasks, const int sys_nr, const int sys_nr_compat, enum trace_flags trace)
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

		if (is_required_syscall(&regs, pid, sys_nr, sys_nr_compat)) {
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

int compel_mode_native(struct parasite_ctl *ctl)
{
	return user_regs_native(&ctl->orig.regs);
}

static inline k_rtsigset_t *thread_ctx_sigmask(struct thread_ctx *tctx)
{
	return &tctx->sigmask;
}

k_rtsigset_t *compel_thread_sigmask(struct parasite_thread_ctl *tctl)
{
	return thread_ctx_sigmask(&tctl->th);
}

k_rtsigset_t *compel_task_sigmask(struct parasite_ctl *ctl)
{
	return thread_ctx_sigmask(&ctl->orig);
}

int compel_get_thread_regs(struct parasite_thread_ctl *tctl, save_regs_t save, void *arg)
{
	return compel_get_task_regs(tctl->tid, &tctl->th.regs, &tctl->th.ext_regs, save, arg, tctl->ctl->ictx.flags);
}

struct infect_ctx *compel_infect_ctx(struct parasite_ctl *ctl)
{
	return &ctl->ictx;
}

struct parasite_blob_desc *compel_parasite_blob_desc(struct parasite_ctl *ctl)
{
	return &ctl->pblob;
}

uint64_t compel_get_leader_sp(struct parasite_ctl *ctl)
{
	return REG_SP(ctl->orig.regs);
}

uint64_t compel_get_thread_sp(struct parasite_thread_ctl *tctl)
{
	return REG_SP(tctl->th.regs);
}

uint64_t compel_get_leader_ip(struct parasite_ctl *ctl)
{
	return REG_IP(ctl->orig.regs);
}

uint64_t compel_get_thread_ip(struct parasite_thread_ctl *tctl)
{
	return REG_IP(tctl->th.regs);
}

void compel_set_leader_ip(struct parasite_ctl *ctl, uint64_t v)
{
	SET_REG_IP(ctl->orig.regs, v);
}

void compel_set_thread_ip(struct parasite_thread_ctl *tctl, uint64_t v)
{
	SET_REG_IP(tctl->th.regs, v);
}
