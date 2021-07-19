#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <signal.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Check how file systems are dumped if some mount points are overmounted";
const char *test_author = "Andrei Vagin <avagin@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	task_waiter_t lock;
	int pid, status = -1;

	test_init(argc, argv);

	task_waiter_init(&lock);

	mkdir(dirname, 0700);

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}
	if (pid == 0) {
		if (mount("zdtm", dirname, "tmpfs", 0, "") < 0) {
			pr_perror("Can't mount tmpfs");
			return 1;
		}
		if (chdir(dirname)) {
			pr_perror("chdir");
			return 1;
		}

		/*
		 * We don't know a direction in which criu enumerates mount,
		 * so lets create two chains of mounts.
		 */

		/* Create a chain when a parent mount is overmounted */
		mkdir("a", 0700);
		mkdir("b", 0700);
		if (mount("zdtm1", "a", "tmpfs", 0, "") || mount("a", "b", NULL, MS_BIND, "")) {
			pr_perror("Can't mount tmpfs");
			return 1;
		}

		mkdir("a/b", 0700);
		mkdir("a/b/c", 0700);
		if (mount("a/b", "a", NULL, MS_BIND, "")) {
			pr_perror("mount");
			return 1;
		}

		if (mount("b", "a/c", NULL, MS_MOVE, "")) {
			pr_perror("Can't mount tmpfs");
			return 1;
		}

		/* create a second chain where a child mount is overmounted*/
		if (mount("zdtm2", "b", "tmpfs", 0, "")) {
			pr_perror("can't mount tmpfs");
			return 1;
		}
		mkdir("b/b", 0700);
		mkdir("b/b/z", 0700);
		if (mount("b", "b/b", NULL, MS_BIND, NULL) || mount("b/b/b", "b/b", NULL, MS_BIND, NULL)) {
			pr_perror("can't mount tmpfs");
			return 1;
		}

		task_waiter_complete(&lock, 1);

		test_waitsig();
		if (umount2("a", MNT_DETACH)) {
			pr_perror("umount");
			return 1;
		}
		if (umount2("b/b", MNT_DETACH) || umount2("b/b", MNT_DETACH)) {
			pr_perror("umount");
			return 1;
		}

		if (access("a/b/c", R_OK) || access("b/b/z", R_OK)) {
			pr_perror("access");
			return 1;
		}
		return 0;
	}

	task_waiter_wait4(&lock, 1);

	test_daemon();
	test_waitsig();

	kill(pid, SIGTERM);
	wait(&status);
	if (status) {
		fail();
		return 1;
	}

	pass();
	return 0;
}
