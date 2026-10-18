#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Check that new pids stay above the ones in use after restore";
const char *test_author = "Alex Xu <ax2155@columbia.edu>";

#define NR_FORKS 1000

static int read_last_pid(void)
{
	FILE *f;
	int pid;

	f = fopen("/proc/sys/kernel/ns_last_pid", "r");
	if (!f) {
		pr_perror("Can't open ns_last_pid");
		return -1;
	}
	if (fscanf(f, "%d", &pid) != 1) {
		pr_perror("Can't read ns_last_pid");
		pid = -1;
	}
	fclose(f);
	return pid;
}

static pid_t fork_one(void)
{
	pid_t pid = fork();

	if (pid < 0) {
		pr_perror("fork");
		return -1;
	}
	if (pid == 0)
		_exit(0);
	if (waitpid(pid, NULL, 0) != pid) {
		pr_perror("waitpid");
		return -1;
	}
	return pid;
}

int main(int argc, char **argv)
{
	int before, after, i;
	pid_t pid;

	test_init(argc, argv);

	/* Move the allocator well past our own pid */
	for (i = 0; i < NR_FORKS; i++)
		if (fork_one() < 0)
			return 1;

	before = read_last_pid();
	if (before < 0)
		return 1;

	test_daemon();
	test_waitsig();

	after = read_last_pid();
	pid = fork_one();
	if (after < 0 || pid < 0)
		return 1;

	if (pid <= before)
		fail("new child got pid %d, the allocator was at %d before dump and %d after restore", pid, before, after);
	else
		pass();

	return 0;
}
