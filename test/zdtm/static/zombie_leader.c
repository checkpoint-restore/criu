#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "zdtmtst.h"

const char *test_doc = "Check non-empty session with zombie leader";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

int child(void)
{
	while (1)
		sleep(1);

	return 0;
}

int zombie_leader(int *cpid)
{
	int pid;

	setsid();

	pid = fork();
	if (pid < 0) {
		pr_perror("Failed to fork child");
		return 1;
	} else if (pid == 0) {
		exit(child());
	}

	*cpid = pid;
	return 0;
}

int main(int argc, char **argv)
{
	int ret = -1, status;
	int pid, *cpid;
	siginfo_t infop;

	test_init(argc, argv);

	cpid = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	*cpid = 0;

	pid = fork();
	if (pid < 0) {
		pr_perror("Failed to fork zombie");
		return 1;
	} else if (pid == 0) {
		exit(zombie_leader(cpid));
	}

	if (waitid(P_PID, pid, &infop, WNOWAIT | WEXITED) < 0) {
		pr_perror("Failed to waitid zombie");
		goto err;
	}

	if (!*cpid) {
		pr_err("Don't know grand child's pid\n");
		goto err;
	}

	test_daemon();
	test_waitsig();

	ret = 0;
err:
	waitpid(pid, &status, 0);

	if (*cpid)
		kill(*cpid, SIGKILL);

	if (!ret)
		pass();

	return 0;
}
