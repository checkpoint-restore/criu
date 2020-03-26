#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check nested time namespaces";
const char *test_author	= "Andrei Vagin <avagin@gmail.com";


#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME   0x00000080
#endif

int main(int argc, char **argv)
{
	pid_t pid;
	int fd;

	test_init(argc, argv);

	fd = open("/proc/self/ns/time", O_RDONLY);
	if (fd < 0) {
		pr_perror("Unable to open /proc/self/ns/time");
		return 1;
	}

	if (unshare(CLONE_NEWTIME)) {
		pr_perror("unshare");
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return -1;
	}

	if (pid == 0) {
		while (1)
			sleep(1);
		return 0;
	}
	if (setns(fd, 0) < 0) {
		kill(pid, SIGKILL);
		wait(NULL);
		pr_perror("Unable to restore time namespace");
		return 1;
	}
	close(fd);

	test_daemon();
	test_waitsig();

	kill(pid, SIGKILL);
	wait(NULL);

	pass();

	return 0;
}
