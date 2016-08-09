#define _GNU_SOURCE
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/mount.h>
#include <dirent.h>

#include "zdtmtst.h"

const char *test_doc	= "Check a case when a root is read-only for a sub-mntns";
const char *test_author	= "Andrew Vagin <avagin@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);


int main(int argc, char **argv)
{
	task_waiter_t lock;
	pid_t pid = -1;
	int status = 1;

	task_waiter_init(&lock);
	test_init(argc, argv);

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}

	if (pid == 0) {
		if (unshare(CLONE_NEWNS)) {
			pr_perror("unshare");
			return 1;
		}
		if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL)) {
			pr_perror("mount");
			return 1;
		}

		task_waiter_complete(&lock, 1);
		test_waitsig();

		return 0;
	}

	task_waiter_wait4(&lock, 1);
	test_daemon();
	test_waitsig();

	kill(pid, SIGTERM);
	wait(&status);
	if (status) {
		fail("Test died");
		return 1;
	}
	pass();

	return 0;
}
