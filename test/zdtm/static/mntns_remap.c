#include <sched.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Check a case when one mount overmount another one";
const char *test_author = "Andrew Vagin <avagin@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	task_waiter_t t;
	pid_t pid;

	test_init(argc, argv);

	mkdir(dirname, 0755);
	if (mount("zdtm", dirname, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}
	if (chdir(dirname)) {
		pr_perror("chdir");
		return 1;
	}
	mkdir("1", 0755);
	mkdir("2", 0755);
	if (mount("1", "1", NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}
	if (mount(NULL, "1", NULL, MS_PRIVATE, NULL)) {
		pr_perror("mount");
		return 1;
	}
	if (mount("zdtm", "2", "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}
	mkdir("1/a", 0755);
	mkdir("2/a", 0755);
	if (mount("1/a", "1/a", NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}
	if (mount(NULL, "1/a", NULL, MS_SHARED, NULL)) {
		pr_perror("mount");
		return 1;
	}
	if (mount("1/a", "2/a", NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}
	mkdir("1/a/c", 0755);
	if (mount("zdtm", "1/a/c", "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}
	if (mount("2", "1", NULL, MS_MOVE, NULL)) {
		pr_perror("mount");
		return 1;
	}

	task_waiter_init(&t);

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		if (unshare(CLONE_NEWNS))
			return 1;
		task_waiter_complete_current(&t);
		test_waitsig();
		return 0;
	}

	task_waiter_wait4(&t, pid);
	test_daemon();
	test_waitsig();

	kill(pid, SIGTERM);
	wait(NULL);

	pass();

	return 0;
}
