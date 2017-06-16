#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc	= "Check NSpids of dead tasks restore right";
const char *test_author	= "Kirill Tkhai <ktkhai@virtuozzo.com>";

enum {
	FUTEX_INITIALIZED = 0,
	CHILD_PREPARED,
	EMERGENCY_ABORT,
};

futex_t *futex;

#define CHILD_NS_PID 11235
#define PARENT_NS_PID 31415

static int set_ns_next_pid(pid_t pid)
{
	char buf[32];
	int len, fd;

	fd = open("/proc/sys/kernel/ns_last_pid", O_WRONLY);
	if (fd < 0)
		return -1;

	len = snprintf(buf, sizeof(buf), "%d", pid - 1);
	len -= write(fd, buf, len);
	if (len)
		pr_perror("Can't set ns_last_pid");
	close(fd);

	return len ? -1 : 0;
}

static int pause_loop(void)
{
	while (1)
		pause();
	return 0;
}

static int child(void)
{
	if (set_ns_next_pid(CHILD_NS_PID)) {
		futex_set_and_wake(futex, EMERGENCY_ABORT);
		exit(1);
	}

	futex_set_and_wake(futex, CHILD_PREPARED);
	return pause_loop();
}

static int get_ns_pid(pid_t pid, char **str)
{
	char buf[64];
	FILE *fp;
	size_t n;

	snprintf(buf, sizeof(buf), "/proc/%d/status", pid);
	fp = fopen(buf, "r");
	if (!fp) {
		pr_perror("Can't open %s", buf);
		return -1;
	}

	*str = NULL;
	while (getline(str, &n, fp) != -1) {
		if (strncmp(*str, "NSpid:", 6) == 0) {
			fclose(fp);
			return 0;
		}
	}

	pr_err("NSpid has not found\n");
	free(*str);
	fclose(fp);
	return -1;
}
/*
 * 1)Create a pid namespace and child reaper in it;
 * 2)Set a specific next pid for future created process;
 * 3)Create one more process in the namespace and kill it;
 * 4)Wait for signal
 * 5)Check, that NSpids of dead task remains the same.
 */
int main(int argc, char **argv)
{
	int i, status, ret = -1;
	pid_t pid[] = {-1, -1};
	char *ns_pid, *tmp;
	siginfo_t infop;

	test_init(argc, argv);
	futex = mmap(NULL, sizeof(*futex), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (futex == MAP_FAILED) {
		fail("mmap futex\n");
		return 1;
	}
	futex_init(futex);

	if (unshare(CLONE_NEWPID) < 0) {
		fail("Can't unshare");
		return 1;
	}

	/* Create child 1, child reaper of the new namespace */
	pid[0] = fork();
	if (pid[0] < 0) {
		fail("Can't fork");
		return 1;
	} else if (pid[0] == 0)
		exit(child());

	futex_wait_while_lt(futex, CHILD_PREPARED);
	if (futex_get(futex) == EMERGENCY_ABORT) {
		pr_err("Fail during prepare of child 1\n");
		goto out;
	}

	if (set_ns_next_pid(PARENT_NS_PID)) {
		pr_err("Fail during next pid write\n");
		goto out;
	}

	/* Child 2 is in the same namespace as child 1 */
	pid[1] = fork();
	if (pid[1] < 0) {
		pr_perror("Can't fork");
		goto out;
	} else if (pid[1] == 0)
		exit(pause_loop());

	if (get_ns_pid(pid[1], &ns_pid) < 0) {
		pr_perror("Can't get ns_pid");
		goto out;
	}

	if (kill(pid[1], SIGKILL)) {
		fail("Can't kill");
		goto out;
	}
	ret = waitid(P_PID, pid[1], &infop, WEXITED|WNOWAIT);
	if (ret) {
		fail("Can't wait");
		goto out;
	}

	test_daemon();
	test_waitsig();

	if (get_ns_pid(pid[1], &tmp) < 0) {
		pr_perror("Can't fork");
		goto out;
	}

	if (strcmp(ns_pid, tmp)) {
		pr_err("NSpid mismatch: %s %s\n", ns_pid, tmp);
		goto out;
	}

	ret = 0;
out:
	/* Wait child reaper last as it waits namespace processes itself */
	for (i = 1; i >= 0; i--) {
		kill(pid[i], SIGKILL);
		waitpid(pid[i], &status, 0);
	}
	if (ret)
		fail("Test failed");
	else
		pass();
	return ret;
}
