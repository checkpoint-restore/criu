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

#include "zdtmtst.h"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS     0x00020000
#endif

const char *test_doc	= "Check bind-mouns of the root mount";
const char *test_author	= "Andrew Vagin <avagin@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);


int main(int argc, char **argv)
{
	char path[PATH_MAX], bpath[PATH_MAX], spath[PATH_MAX], bspath[PATH_MAX];
	pid_t pid;
	int status;
	task_waiter_t t;

	test_init(argc, argv);

	task_waiter_init(&t);

	mount(NULL, "/", NULL, MS_SHARED, NULL);

	snprintf(path, sizeof(path), "%s/test", dirname);
	snprintf(bpath, sizeof(bpath), "%s/test.bind", dirname);
	snprintf(spath, sizeof(spath), "%s/test/sub", dirname);
	snprintf(bspath, sizeof(bspath), "%s/test.bind/sub", dirname);

	if (mkdir(dirname, 0700) ||
	    mkdir(path, 0700) ||
	    mkdir(spath, 0700) ||
	    mkdir(bpath, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}
	if (pid == 0) {
		unshare(CLONE_NEWNS);
		if (mount(path, bpath, NULL, MS_BIND, NULL)) {
			pr_perror("mount");
			return 1;
		}

		task_waiter_complete(&t, 1);
		task_waiter_wait4(&t, 2);

		if (access(bspath, F_OK)) {
			fail("%s isn't accessiable", bspath);
			return 1;
		}


		if (umount2(bpath, MNT_DETACH)) {
			fail("umount");
			return 1;
		}

		return 0;
	}

	task_waiter_wait4(&t, 1);

	if (mount("test", spath, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	test_daemon();
	test_waitsig();

	task_waiter_complete(&t, 2);

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("waitpid %d", pid);
		return 1;
	}

	if (status) {
		pr_perror("%d/%d/%d/%d", WIFEXITED(status), WEXITSTATUS(status), WIFSIGNALED(status), WTERMSIG(status));
		return 1;
	}

	pass();

	return 0;
}
