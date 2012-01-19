#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include "zdtmtst.h"

const char *test_doc = "Tests that forking tasks are handled properly";
const char *test_author = "Pavel Emelyanov <xemul@parallels.com>";

int main(int argc, char **argv)
{
	int pid, wpid, status;

	test_init(argc, argv);
	test_daemon();

	while (test_go()) {
		pid = fork();
		if (pid < 0) {
			fail("Can't fork");
			goto out;
		}

		if (pid == 0)
			exit(0);

		wpid = wait(&status);
		if (wpid != pid) {
			fail("Pids do not match");
			goto out;
		}

		if (!WIFEXITED(status)) {
			fail("Task didn't exit");
			goto out;
		}

		if (WEXITSTATUS(status) != 0) {
			fail("Task exited with wrong code");
			goto out;
		}
	}
	test_waitsig();
	pass();
out:
	return 0;
}
