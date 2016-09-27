#include <sys/ptrace.h>
#include <errno.h>

#include "log.h"
#include "infect.h"

int compel_stop_task(int pid)
{
	int ret;

	ret = ptrace(PTRACE_SEIZE, pid, NULL, 0);
	if (ret) {
		/*
		 * ptrace API doesn't allow to distinguish
		 * attaching to zombie from other errors.
		 * All errors will be handled in seize_wait_task().
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

