#include <sched.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include "zdtmtst.h"

const char *test_doc = "Check that zombie pgid is restored";
const char *test_author = "Kirill Tkhai <ktkhai@virtuozzo.com>";

int main(int argc, char **argv)
{
	pid_t pid, pgrp;
	siginfo_t info;
	int status;

	test_init(argc, argv);

	pid = fork();
	if (pid < 0) {
		fail("fork");
		exit(1);
	}

	if (!pid) {
		/* Child */
		if (setpgid(0, 0) < 0) {
			fail("setpgid");
			exit(1);
		}
		pid = sys_clone_unified(CLONE_PARENT | SIGCHLD, NULL, NULL, NULL, 0);
		if (pid < 0) {
			fail("fork");
			exit(1);
		}

		exit(0);
	}

	if (waitpid(pid, &status, 0) < 0) {
		fail("waitpid");
		exit(1);
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		pr_err("Exited with problems: status=%d\n", status);
		fail("fail");
		exit(1);
	}

	if (waitid(P_ALL, 0, &info, WEXITED | WNOWAIT) < 0) {
		fail("waitpid");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	if (waitid(P_ALL, 0, &info, WEXITED | WNOWAIT) < 0) {
		fail("waitpid");
		exit(1);
	}

	pgrp = getpgid(info.si_pid);
	if (pgrp < 0) {
		fail("getpgrp");
		exit(1);
	}

	if (pgrp != pid) {
		pr_err("Wrong pgrp: %d != %d\n", pgrp, pid);
		fail("fail");
		exit(1);
	}

	pass();
	return 0;
}
