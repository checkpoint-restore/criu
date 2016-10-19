#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <linux/seccomp.h>

#include "infect.h"
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
#include "criu-log.h"
#include "infect-rpc.h"
#include "infect-priv.h"

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

int compel_unseize_task(pid_t pid, int orig_st, int st)
{
	pr_debug("\tUnseizing %d into %d\n", pid, st);

	if (st == TASK_DEAD) {
		kill(pid, SIGKILL);
		return 0;
	} else if (st == TASK_STOPPED) {
		/*
		 * Task might have had STOP in queue. We detected such
		 * guy as TASK_STOPPED, but cleared signal to run the
		 * parasite code. hus after detach the task will become
		 * running. That said -- STOP everyone regardless of
		 * the initial state.
		 */
		kill(pid, SIGSTOP);
	} else if (st == TASK_ALIVE) {
		/*
		 * Same as in the comment above -- there might be a
		 * task with STOP in queue that would get lost after
		 * detach, so stop it again.
		 */
		if (orig_st == TASK_STOPPED)
			kill(pid, SIGSTOP);
	} else
		pr_err("Unknown final state %d\n", st);

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		pr_perror("Unable to detach from %d", pid);
		return -1;
	}

	return 0;
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

static int restore_child_handler()
{
	struct sigaction sa = {
		.sa_handler	= SIG_DFL, /* XXX -- should be original? */
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


int compel_execute_syscall(struct parasite_ctl *ctl,
		user_regs_struct_t *regs, const char *code_syscall)
{
	pid_t pid = ctl->rpid;
	int err;
	u8 code_orig[BUILTIN_SYSCALL_SIZE];

	/*
	 * Inject syscall instruction and remember original code,
	 * we will need it to restore original program content.
	 */
	memcpy(code_orig, code_syscall, sizeof(code_orig));
	if (ptrace_swap_area(pid, (void *)ctl->ictx.syscall_ip,
			     (void *)code_orig, sizeof(code_orig))) {
		pr_err("Can't inject syscall blob (pid: %d)\n", pid);
		return -1;
	}

	err = parasite_run(pid, PTRACE_CONT, ctl->ictx.syscall_ip, 0, regs, &ctl->orig);
	if (!err)
		err = parasite_trap(ctl, pid, regs, &ctl->orig);

	if (ptrace_poke_area(pid, (void *)code_orig,
			     (void *)ctl->ictx.syscall_ip, sizeof(code_orig))) {
		pr_err("Can't restore syscall blob (pid: %d)\n", ctl->rpid);
		err = -1;
	}

	return err;
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

	args = compel_parasite_args(ctl, struct parasite_init_args);

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
	 * compel_get_task_regs needs to call ptrace on _stopped_ task,
	 * while in daemon it is not such.
	 */

	if (compel_get_task_regs(pid, ctl->orig.regs, ictx->save_regs, ictx->regs_arg)) {
		pr_err("Can't obtain regs for thread %d\n", pid);
		return -1;
	}

	if (ictx->make_sigframe(ictx->regs_arg, ctl->sigframe, ctl->rsigframe, &ctl->orig.sigmask))
		return -1;

	if (parasite_init_daemon(ctl))
		return -1;

	return 0;
}

static int parasite_mmap_exchange(struct parasite_ctl *ctl, unsigned long size)
{
	int fd;

	ctl->remote_map = mmap_seized(ctl, NULL, size,
				      PROT_READ | PROT_WRITE | PROT_EXEC,
				      MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (!ctl->remote_map) {
		pr_err("Can't allocate memory for parasite blob (pid: %d)\n", ctl->rpid);
		return -1;
	}

	ctl->map_length = round_up(size, page_size());

	fd = open_proc_rw(ctl->rpid, "map_files/%p-%p",
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

static int parasite_memfd_exchange(struct parasite_ctl *ctl, unsigned long size)
{
	void *where = (void *)ctl->ictx.syscall_ip + BUILTIN_SYSCALL_SIZE;
	u8 orig_code[MEMFD_FNAME_SZ] = MEMFD_FNAME;
	pid_t pid = ctl->rpid;
	unsigned long sret = -ENOSYS;
	int ret, fd, lfd;
	bool __maybe_unused compat_task = !compel_mode_native(ctl);

	if (ctl->ictx.flags & INFECT_NO_MEMFD)
		return 1;

	BUILD_BUG_ON(sizeof(orig_code) < sizeof(long));

	if (ptrace_swap_area(pid, where, (void *)orig_code, sizeof(orig_code))) {
		pr_err("Can't inject memfd args (pid: %d)\n", pid);
		return -1;
	}

	ret = syscall_seized(ctl, __NR(memfd_create, compat_task), &sret,
			     (unsigned long)where, 0, 0, 0, 0, 0);

	if (ptrace_poke_area(pid, orig_code, where, sizeof(orig_code))) {
		fd = (int)(long)sret;
		if (fd >= 0)
			syscall_seized(ctl, __NR(close, compat_task), &sret,
					fd, 0, 0, 0, 0, 0);
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
	lfd = open_proc_rw(ctl->rpid, "fd/%d", fd);
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

	syscall_seized(ctl, __NR(close, compat_task), &sret, fd, 0, 0, 0, 0, 0);
	close(lfd);

	pr_info("Set up parasite blob using memfd\n");
	return 0;

err_curef:
	close(lfd);
err_cure:
	syscall_seized(ctl, __NR(close, compat_task), &sret, fd, 0, 0, 0, 0, 0);
	return -1;
}

int compel_map_exchange(struct parasite_ctl *ctl, unsigned long size)
{
	int ret;

	ret = parasite_memfd_exchange(ctl, size);
	if (ret == 1) {
		pr_info("MemFD parasite doesn't work, goto legacy mmap\n");
		ret = parasite_mmap_exchange(ctl, size);
	}
	return ret;
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

	if (compel_mode_native(ctl))
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

	ret = compel_map_exchange(ctl, map_exchange_size);
	if (ret)
		goto err;

	pr_info("Putting parasite blob into %p->%p\n", ctl->local_map, ctl->remote_map);

	if (compel_mode_native(ctl))
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

int compel_prepare_thread(int pid, struct thread_ctx *ctx)
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

struct parasite_ctl *compel_prepare(int pid)
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

	if (compel_prepare_thread(pid, &ctl->orig))
		goto err;

	ctl->rpid = pid;

	BUILD_BUG_ON(PARASITE_START_AREA_MIN < BUILTIN_SYSCALL_SIZE + MEMFD_FNAME_SZ);

	return ctl;

err:
	xfree(ctl);
	return NULL;
}

static bool task_in_parasite(struct parasite_ctl *ctl, user_regs_struct_t *regs)
{
	void *addr = (void *) REG_IP(*regs);
	return addr >= ctl->remote_map &&
		addr < ctl->remote_map + ctl->map_length;
}

static int parasite_fini_seized(struct parasite_ctl *ctl)
{
	pid_t pid = ctl->rpid;
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

	ret = compel_rpc_call(PARASITE_CMD_FINI, ctl);
	close_safe(&ctl->tsock);
	if (ret)
		return -1;

	/* Go to sigreturn as closer as we can */
	ret = compel_stop_pie(pid, ctl->sigreturn_addr, &flag,
			ctl->ictx.flags & INFECT_NO_BREAKPOINTS);
	if (ret < 0)
		return ret;

	if (compel_stop_on_syscall(1, __NR(rt_sigreturn, 0),
				__NR(rt_sigreturn, 1), flag))
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
	if (compel_stop_daemon(ctl))
		return -1;

	if (!ctl->remote_map)
		return 0;

	/* Unseizing task with parasite -- it does it himself */
	if (ctl->addr_cmd) {
		struct parasite_unmap_args *args;

		*ctl->addr_cmd = PARASITE_CMD_UNMAP;

		args = compel_parasite_args(ctl, struct parasite_unmap_args);
		args->parasite_start = ctl->remote_map;
		args->parasite_len = ctl->map_length;
		if (compel_unmap(ctl, ctl->parasite_ip))
			return -1;
	} else {
		unsigned long ret;

		syscall_seized(ctl, __NR(munmap, !compel_mode_native(ctl)), &ret,
				(unsigned long)ctl->remote_map, ctl->map_length,
				0, 0, 0, 0);
		if (ret) {
			pr_err("munmap for remote map %p, %lu returned %lu\n",
					ctl->remote_map, ctl->map_length, ret);
			return -1;
		}
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
	return ctl->addr_args;
}

void *compel_parasite_args_s(struct parasite_ctl *ctl, int args_size)
{
	BUG_ON(args_size > ctl->args_size);
	return compel_parasite_args_p(ctl);
}

int compel_run_in_thread(pid_t pid, unsigned int cmd,
					struct parasite_ctl *ctl,
					struct thread_ctx *octx)
{
	void *stack = ctl->r_thread_stack;
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

/*
 * compel_unmap() is used for unmapping parasite and restorer blobs.
 * A blob can contain code for unmapping itself, so the porcess is
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

	ret = compel_stop_on_syscall(1, __NR(munmap, 0),
			__NR(munmap, 1), TRACE_ENTER);

	if (restore_thread_ctx(pid, &ctl->orig))
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
		pr_err("Task signaled with %d: %s\n",
			WTERMSIG(status), strsignal(WTERMSIG(status)));
	if (WIFSTOPPED(status))
		pr_err("Task stopped with %d: %s\n",
			WSTOPSIG(status), strsignal(WSTOPSIG(status)));
	if (WIFCONTINUED(status))
		pr_err("Task continued\n");

	return false;
}

static inline int is_required_syscall(user_regs_struct_t *regs, pid_t pid,
		const int sys_nr, const int sys_nr_compat)
{
	const char *mode = user_regs_native(regs) ? "native" : "compat";
	int req_sysnr = user_regs_native(regs) ? sys_nr : sys_nr_compat;

	pr_debug("%d (%s) is going to execute the syscall %lu, required is %d\n",
		pid, mode, REG_SYSCALL_NR(*regs), req_sysnr);

	return (REG_SYSCALL_NR(*regs) == req_sysnr);
}

/*
 * Trap tasks on the exit from the specified syscall
 *
 * tasks - number of processes, which should be trapped
 * sys_nr - the required syscall number
 * sys_nr_compat - the required compatible syscall number
 */
int compel_stop_on_syscall(int tasks,
	const int sys_nr, const int sys_nr_compat,
	enum trace_flags trace)
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

k_rtsigset_t *compel_task_sigmask(struct parasite_ctl *ctl)
{
	return &ctl->orig.sigmask;
}

struct infect_ctx *compel_infect_ctx(struct parasite_ctl *ctl)
{
	return &ctl->ictx;
}
