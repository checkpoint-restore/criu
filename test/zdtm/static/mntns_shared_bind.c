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
#define CLONE_NEWNS 0x00020000
#endif

const char *test_doc = "Check shared non-root bind-mounts";
const char *test_author = "Andrew Vagin <avagin@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char path[PATH_MAX], bpath[PATH_MAX], spath[PATH_MAX];
	pid_t pid;
	int status;
	task_waiter_t t;

	test_init(argc, argv);

	task_waiter_init(&t);

	snprintf(path, sizeof(path), "%s/test", dirname);
	snprintf(bpath, sizeof(bpath), "%s/test.bind", dirname);
	snprintf(spath, sizeof(spath), "%s/test/sub", dirname);
	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount(NULL, "/", NULL, MS_SHARED, NULL)) {
		pr_perror("mount");
		return 1;
	}

#ifdef SHARED_BIND02
	/* */
	if (mount(dirname, dirname, "tmpfs", 0, NULL) || mount(NULL, dirname, NULL, MS_SHARED, NULL)) {
		pr_perror("mount");
		return 1;
	}
#endif

	if (mkdir(path, 0700) || mkdir(spath, 0700) || mkdir(bpath, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

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
		if (mount(path, bpath, NULL, MS_BIND, NULL)) {
			pr_perror("mount");
			return 1;
		}

		task_waiter_complete(&t, 1);
		task_waiter_wait4(&t, 2);
		if (umount(spath)) {
			task_waiter_complete(&t, 2);
			fail("umount");
			return 1;
		}
		task_waiter_complete(&t, 3);
		task_waiter_wait4(&t, 4);

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
	task_waiter_wait4(&t, 3);

	if (umount(bpath)) {
		task_waiter_complete(&t, 2);
		fail("umount");
		return 1;
	}

	task_waiter_complete(&t, 4);

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
