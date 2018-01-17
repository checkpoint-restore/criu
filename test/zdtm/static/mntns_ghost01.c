#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/wait.h>
#include <limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check ghost file is restored on readonly fs if it was ghost-remaped on writable bind";
const char *test_author	= "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);


int main(int argc, char **argv)
{
	char ghost_path[PATH_MAX];
	task_waiter_t lock;
	pid_t pid = -1;
	int status = 1;
	int pfd;

	test_init(argc, argv);
	task_waiter_init(&lock);

	if (mkdir(dirname, 0600) < 0) {
		pr_perror("mkdir");
		return 1;
	}

	snprintf(ghost_path, PATH_MAX, "%s/test.ghost", dirname);

	pfd = open(ghost_path, O_CREAT | O_WRONLY, 0600);
	if (pfd < 0) {
		pr_perror("open");
		return 1;
	}
	close(pfd);

	pfd = open(ghost_path, O_RDONLY);
	if (pfd < 0) {
		pr_perror("open");
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}

	if (pid == 0) {
		int fd;

		if (unshare(CLONE_NEWNS)) {
			pr_perror("unshare");
			return 1;
		}

		if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
			pr_perror("mount");
			return 1;
		}

		if (mount(dirname, dirname, NULL, MS_BIND, NULL)) {
			pr_perror("mount");
			return 1;
		}

		if (mount(NULL, dirname, NULL, MS_RDONLY|MS_REMOUNT|MS_BIND, NULL)) {
			pr_perror("remount");
			return 1;
		}

		fd = open(ghost_path, O_RDONLY);
		if (fd < 0) {
			pr_perror("open");
			return 1;
		}

		task_waiter_complete(&lock, 1);
		test_waitsig();

		if (close(fd)) {
			pr_perror("close");
			return 1;
		}

		return 0;
	}

	task_waiter_wait4(&lock, 1);

	if (unlink(ghost_path)) {
		pr_perror("unlink");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (close(pfd)) {
		pr_perror("close");
		return 1;
	}

	kill(pid, SIGTERM);
	wait(&status);
	if (status) {
		fail("Test died");
		return 1;
	}
	pass();

	return 0;
}
