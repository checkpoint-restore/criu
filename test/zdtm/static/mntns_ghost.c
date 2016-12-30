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

const char *test_doc	= "Check ghost and link-remap files in a few mntns";
const char *test_author	= "Andrew Vagin <avagin@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);


int main(int argc, char **argv)
{
	task_waiter_t lock;
	pid_t pid = -1;
	int status = 1;

	test_init(argc, argv);
	task_waiter_init(&lock);

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}

	if (pid == 0) {
		int fd;
		DIR *d;
		struct dirent *de;

		if (unshare(CLONE_NEWNS)) {
			pr_perror("unshare");
			return 1;
		}
		if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
			pr_perror("mount");
			return 1;
		}

		if (mkdir(dirname, 0600) < 0) {
			pr_perror("mkdir");
			return 1;
		}

		if (mount(dirname, dirname, NULL, MS_BIND, NULL)) {
			pr_perror("mount");
			return 1;
		}
		if (chdir(dirname))
			return 1;

		fd = open("test.ghost", O_CREAT | O_WRONLY, 0600);
		if (fd < 0) {
			pr_perror("open");
			return 1;
		}

		if (unlink("test.ghost")) {
			pr_perror("unlink");
			return 1;
		}

		task_waiter_complete(&lock, 1);
		test_waitsig();

		if (close(fd)) {
			pr_perror("close");
			return 1;
		}
		d = opendir(".");
		if (d == NULL) {
			pr_perror("opendir");
			return 1;
		}
		while ((de = readdir(d)) != NULL) {
			if (!strcmp(de->d_name, "."))
				continue;
			if (!strcmp(de->d_name, ".."))
				continue;
			pr_err("%s\n", de->d_name);
		}
		closedir(d);

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
