#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include "zdtmtst.h"

const char *test_doc = "Tests that forking tasks are handled properly";
const char *test_author = "Pavel Emelyanov <xemul@parallels.com>";

char children[] = "0123456789";

int main(int argc, char **argv)
{
	int pid, wpid, status;
	int p[2];

	test_init(argc, argv);

	if (pipe(p)) {
		err("pipe");
		return -1;
	}

	if (write(p[1], children, sizeof(children)) != sizeof(children)) {
		err("write");
		return -1;
	}

	test_daemon();

	while (test_go()) {
		char c = 0;
		int ret;

		ret = read(p[0], &children, sizeof(children));
		if (ret <= 0) {
			err("read");
			return 1;
		}

		for (; ret > 0; ret--) {
			pid = fork();
			if (pid < 0) {
				fail("Can't fork");
				goto out;
			}

			if (pid == 0) {
#ifdef FORK2
				usleep(10000);
#endif
				if (write(p[1], &c, 1) != 1) {
					err("write");
					return 1;
				}
				exit(0);
			}
		}

		while (1) {
			wpid = waitpid(-1, &status, WNOHANG);
			if (wpid < 0) {
				if (errno == ECHILD)
					break;
				err("waitpid");
				return -1;
			}
			if (wpid == 0)
				break;

			if (!WIFEXITED(status)) {
				fail("Task %d didn't exit", wpid);
				goto out;
			}

			if (WEXITSTATUS(status) != 0) {
				fail("Task %d exited with wrong code", wpid);
				goto out;
			}
		}

	}
	pass();
out:
	return 0;
}
