#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "compiler.h"
#include "asm/types.h"
#include "util.h"
#include "ptrace.h"
#include "proc_parse.h"
#include "crtools.h"
#include "security.h"

int unseize_task(pid_t pid, int orig_st, int st)
{
	pr_debug("\tUnseizing %d into %d\n", pid, st);

	if (st == TASK_DEAD)
		kill(pid, SIGKILL);
	else if (st == TASK_STOPPED) {
		if (orig_st == TASK_ALIVE)
			kill(pid, SIGSTOP);
	} else if (st == TASK_ALIVE)
		/* do nothing */ ;
	else
		pr_err("Unknown final state %d\n", st);

	return ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

/*
 * This routine seizes task putting it into a special
 * state where we can manipulate the task via ptrace
 * interface, and finally we can detach ptrace out of
 * of it so the task would not know if it was saddled
 * up with someone else.
 */

int seize_task(pid_t pid, pid_t ppid)
{
	siginfo_t si;
	int status;
	int ret, ret2, ptrace_errno, wait_errno = 0;
	struct proc_status_creds cr;

	ret = ptrace(PTRACE_SEIZE, pid, NULL, 0);
	ptrace_errno = errno;
	if (ret == 0) {
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
			pr_perror("SEIZE %d: can't interrupt task", pid);
			ptrace(PTRACE_DETACH, pid, NULL, NULL);
			goto err;
		}
	}

	/*
	 * It's ugly, but the ptrace API doesn't allow to distinguish
	 * attaching to zombie from other errors. Thus we have to parse
	 * the target's /proc/pid/stat. Sad, but parse whatever else
	 * we might nead at that early point.
	 */

try_again:
	if (!ret) {
		ret = wait4(pid, &status, __WALL, NULL);
		wait_errno = errno;
	}

	ret2 = parse_pid_status(pid, &cr);
	if (ret2)
		goto err;

	if (!may_dump(&cr)) {
		pr_err("Check uid (pid: %d) failed\n", pid);
		goto err;
	}

	if (ret < 0) {
		if (cr.state != 'Z') {
			if (pid == getpid())
				pr_err("The criu itself is within dumped tree.\n");
			else
				pr_err("Unseizable non-zombie %d found, state %c, err %d/%d/%d\n",
						pid, cr.state, ret, ptrace_errno, wait_errno);
			return -1;
		}

		return TASK_DEAD;
	}

	if ((ppid != -1) && (cr.ppid != ppid)) {
		pr_err("Task pid reused while suspending (%d: %d -> %d)\n",
				pid, ppid, cr.ppid);
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

	if (si.si_signo == SIGTRAP)
		return TASK_ALIVE;
	else if (si.si_signo == SIGSTOP) {
		/*
		 * PTRACE_SEIZE doesn't affect signal or group stop state.
		 * Currently ptrace reported that task is in stopped state.
		 * We need to start task again, and it will be trapped
		 * immediately, because we sent PTRACE_INTERRUPT to it.
		 */
		ret = ptrace(PTRACE_CONT, pid, 0, 0);
		if (ret) {
			pr_perror("Unable to start process");
			goto err_stop;
		}

		ret = wait4(pid, &status, __WALL, NULL);
		if (ret < 0) {
			pr_perror("SEIZE %d: can't wait task", pid);
			goto err_stop;
		}

		if (ret != pid) {
			pr_err("SEIZE %d: wrong task attached (%d)\n", pid, ret);
			goto err_stop;
		}

		if (!WIFSTOPPED(status)) {
			pr_err("SEIZE %d: task not stopped after seize\n", pid);
			goto err_stop;
		}

		return TASK_STOPPED;
	} else {
		pr_err("SEIZE %d: unsupported stop signal %d\n", pid, si.si_signo);
		goto err;
	}

err_stop:
	kill(pid, SIGSTOP);
err:
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	return -1;
}

int ptrace_peek_area(pid_t pid, void *dst, void *addr, long bytes)
{
	unsigned long w;
	if (bytes & (sizeof(long) - 1))
		return -1;
	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *d = dst, *a = addr;
		d[w] = ptrace(PTRACE_PEEKDATA, pid, a + w, NULL);
		if (d[w] == -1U && errno)
			goto err;
	}
	return 0;
err:
	return -2;
}

int ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes)
{
	unsigned long w;
	if (bytes & (sizeof(long) - 1))
		return -1;
	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *s = src, *a = addr;
		if (ptrace(PTRACE_POKEDATA, pid, a + w, s[w]))
			goto err;
	}
	return 0;
err:
	return -2;
}

/* don't swap big space, it might overflow the stack */
int ptrace_swap_area(pid_t pid, void *dst, void *src, long bytes)
{
	void *t = alloca(bytes);

	if (ptrace_peek_area(pid, t, dst, bytes))
		return -1;

	if (ptrace_poke_area(pid, src, dst, bytes)) {
		if (ptrace_poke_area(pid, t, dst, bytes))
			return -2;
		return -1;
	}

	memcpy(src, t, bytes);

	return 0;
}
