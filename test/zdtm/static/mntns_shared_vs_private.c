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

#include "zdtmtst.h"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS     0x00020000
#endif

const char *test_doc	= "Check a private mount in a shared mount";
const char *test_author	= "Andrew Vagin <avagin@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);


int main(int argc, char **argv)
{
	char path[PATH_MAX];
	pid_t pid;
	int status, i;
	task_waiter_t t;

	test_init(argc, argv);

	task_waiter_init(&t);

	snprintf(path, sizeof(path), "%s/fs", dirname);
	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount(NULL, "/", NULL, MS_SHARED, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount("zdtm_fs", dirname, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount(NULL, dirname, NULL, MS_PRIVATE, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mkdir(path, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("zdtm_fs", path, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	for (i = 0; i < 2; i++) {
		pid = fork();
		if (pid < 0) {
			pr_perror("fork");
			return 1;
		}
		if (pid == 0) {
			unshare(CLONE_NEWNS);

			task_waiter_complete(&t, 1);
			task_waiter_wait4(&t, 2);

			return 0;
		}
	}

	for (i = 0; i < 2; i++)
		task_waiter_wait4(&t, 1);

	test_daemon();
	test_waitsig();

	if (umount(path)) {
		pr_perror("Unable to umount %s", path);
		return 1;
	}
	if (umount(dirname)) {
		pr_perror("Unable to umount %s", dirname);
		return 1;
	}

	for (i = 0; i < 2; i++) {
		task_waiter_complete(&t, 2);

		if (waitpid(-1, &status, 0) < 0) {
			pr_perror("waitpid %d", pid);
			return 1;
		}

		if (status) {
			pr_err("%d/%d/%d/%d\n", WIFEXITED(status), WEXITSTATUS(status), WIFSIGNALED(status), WTERMSIG(status));
			return 1;
		}
	}

	pass();

	return 0;
}
