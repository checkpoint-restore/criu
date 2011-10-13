#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>

#include <fcntl.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "compiler.h"
#include "types.h"
#include "list.h"
#include "util.h"
#include "seize.h"

#include "crtools.h"

int unseize_task(pid_t pid)
{
	return ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

/*
 * This routine seizes task putting it into a special
 * state where we can manipulate the task via ptrace
 * inteface, and finally we can detach ptrace out of
 * of it so the task would not know if it was saddled
 * up with someone else.
 */
int seize_task(pid_t pid)
{
	siginfo_t si;
	int status;
	int ret = 0;

	jerr_rc(ptrace(PTRACE_SEIZE, pid, NULL,
		       (void *)(unsigned long)PTRACE_SEIZE_DEVEL), ret, err);
	jerr_rc(ptrace(PTRACE_INTERRUPT, pid, NULL, NULL), ret, err);

	ret = -10;
	if (wait4(pid, &status, __WALL, NULL) != pid)
		goto err;

	ret = -20;
	if (!WIFSTOPPED(status))
		goto err;

	jerr_rc(ptrace(PTRACE_GETSIGINFO, pid, NULL, &si), ret, err_cont);

	ret = -30;
	if ((si.si_code >> 8) != PTRACE_EVENT_STOP)
		goto err_cont;

	jerr_rc(ptrace(PTRACE_SETOPTIONS, pid, NULL,
		       (void *)(unsigned long)PTRACE_O_TRACEEXIT), ret, err_cont);

err:
	return ret;

err_cont:
	continue_task(pid);
	goto err;
}
