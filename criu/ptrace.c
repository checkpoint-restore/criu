#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <signal.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "int.h"
#include "common/compiler.h"
#include "util.h"
#include "ptrace.h"
#include "pid.h"
#include "proc_parse.h"
#include "seccomp.h"
#include "cr_options.h"

int unseize_task(pid_t pid, int orig_st, int st)
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

int suspend_seccomp(pid_t pid)
{
	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_SUSPEND_SECCOMP) < 0) {
		pr_perror("suspending seccomp failed");
		return -1;
	}

	return 0;
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
