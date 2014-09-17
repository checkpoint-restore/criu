#define _GNU_SOURCE
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "zdtmtst.h"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS     0x00020000
#endif

const char *test_doc	= "Check that dead pid's /proc entries are remapped correctly";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

int main(int argc, char **argv)
{
	pid_t pid;

	test_init(argc, argv);

	pid = fork();
	if (pid < 0) {
		fail("fork() failed");
		return -1;
	}

	if (pid == 0) {
		test_msg("child is %d\n", pid);
		/* Child process just sleeps until it is killed. All we need
		 * here is a process to open the mountinfo of. */
		while(1)
			sleep(10);
	} else {
		int fd, ret;
		char path[PATH_MAX];
		pid_t result;

		sprintf(path, "/proc/%d/mountinfo", pid);

		fd = open(path, O_RDONLY);

		/* no matter what, we should kill the child */
		kill(pid, SIGINT);
		result = waitpid(pid, NULL, 0);
		if (result < 0) {
			fail("failed waitpid()");
			return -1;
		}

		if (fd < 0) {
			fail("failed opening %s", path);
			return -1;
		}

		test_daemon();
		test_waitsig();

		ret = fcntl(fd, F_GETFD);
		close(fd);

		if (ret) {
			fail("bad fd after restore");
			return -1;
		}
	}

	pass();
	return 0;
}
