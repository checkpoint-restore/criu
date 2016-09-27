#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <linux/seccomp.h>

#include "log.h"
#include "infect.h"

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

