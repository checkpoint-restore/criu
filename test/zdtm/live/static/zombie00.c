#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "See if we can wait() for a zombified child after migration";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

struct zombie {
	int pid;
	int exited;
	int exitcode;
};

#define NR_ZOMBIES	4

int main(int argc, char ** argv)
{
	int i, status;
	struct zombie zombie[NR_ZOMBIES];

	zombie[0].exited = 1;
	zombie[0].exitcode = 0;

	zombie[1].exited = 1;
	zombie[1].exitcode = 3;

	zombie[2].exited = 0;
	zombie[2].exitcode = SIGKILL;

	zombie[3].exited = 0;
	zombie[3].exitcode = SIGSEGV;

	test_init(argc, argv);

	for (i = 0; i < NR_ZOMBIES; i++) {
		zombie[i].pid = fork();
		if (zombie[i].pid < 0) {
			pr_perror("fork failed");
			exit(1);
		}

		if (zombie[i].pid == 0) {
			if (zombie[i].exited)
				_exit(zombie[i].exitcode);
			else if (zombie[i].exitcode == SIGSEGV)
				*(int *)NULL = 0;
			else
				kill(getpid(), zombie[i].exitcode);

			_exit(13); /* just in case */
		}

		test_msg("kid %d will %d/%d\n", zombie[i].pid,
				zombie[i].exited, zombie[i].exitcode);
	}

	/*
	 * We must wait for zombies to appear, but we cannot use
	 * wait4 here :( Use sleep.
	 */

	for (i = 0; i < NR_ZOMBIES; i++) {
		siginfo_t siginfo;
		if (waitid(P_PID, zombie[i].pid, &siginfo, WNOWAIT | WEXITED)) {
			pr_perror("Unable to wait %d", zombie[i].pid);
			exit(1);
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < NR_ZOMBIES; i++) {
		if (waitpid(zombie[i].pid, &status, 0) != zombie[i].pid) {
			fail("Exit with wrong pid\n");
			exit(1);
		}

		if (zombie[i].exited) {
			if (!WIFEXITED(status)) {
				fail("Not exited, but should (%d)\n", zombie[i].pid);
				exit(1);
			}

			if (WEXITSTATUS(status) != zombie[i].exitcode) {
				fail("Exit with wrong status (%d)\n", zombie[i].pid);
				exit(1);
			}
		} else {
			if (!WIFSIGNALED(status)) {
				fail("Not killed, but should (%d)\n", zombie[i].pid);
				exit(1);
			}

			if (WTERMSIG(status) != zombie[i].exitcode) {
				fail("Killed with wrong signal (%d)\n", zombie[i].pid);
				exit(1);
			}
		}
	}

	pass();
	return 0;
}
