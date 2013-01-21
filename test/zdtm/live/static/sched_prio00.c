#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <string.h>
#include <sched.h>

#include "zdtmtst.h"

const char *test_doc	= "Check sched prios to be preserved";
const char *test_author	= "Pavel Emelyanov <xemul@parallels.com>";

#define NRTASKS	3

static int do_nothing(void)
{
	while (1)
		sleep(10);

	return -1;
}

static void kill_all(int *pid, int n)
{
	int i;

	for (i = 0; i < n; i++)
		kill(pid[i], SIGKILL);
}

int main(int argc, char ** argv)
{
	int pid[NRTASKS], i, parm[NRTASKS], ret;

	test_init(argc, argv);

	parm[0] = -20;
	parm[1] = 19;
	parm[2] = 1;

	for (i = 0; i < NRTASKS; i++) {
		pid[i] = fork();
		if (!pid[i])
			return do_nothing();

		if (setpriority(PRIO_PROCESS, pid[i], parm[i])) {
			err("Can't set prio %d", i);
			kill_all(pid, i);
			return -1;
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < NRTASKS; i++) {
		errno = 0;
		ret = getpriority(PRIO_PROCESS, pid[i]);
		if (errno) {
			fail("No prio for task %d", i);
			break;
		}

		if (ret != parm[i]) {
			fail("Broken nice for %d", i);
			break;
		}
	}

	if (i == NRTASKS)
		pass();

	kill_all(pid, NRTASKS);
	return 0;
}
