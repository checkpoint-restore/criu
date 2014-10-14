#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that environment didn't change";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

int main(int argc, char **argv)
{
	int tmp_pipe[2], i;
	int pids[2], syncfd[2], stat, fail = 0;

	test_init(argc, argv);

	pipe(tmp_pipe);
	pids[0] = test_fork();
	if (pids[0] == 0) {
		close(tmp_pipe[0]);

		setsid();

		close(tmp_pipe[1]);
		test_waitsig();

		if (getpid() != getsid(0))
			exit(1);

		if (getpid() != getpgid(0))
			exit(2);

		test_msg("P1 OK\n");
		exit(0);
	}
	close(tmp_pipe[1]);
	syncfd[0] = tmp_pipe[0];

	pipe(tmp_pipe);
	pids[1] = test_fork();
	if (pids[1] == 0) {
		int tmp_pipe_sub[2], pid;

		close(tmp_pipe[0]);

		setsid();

		pipe(tmp_pipe_sub);
		pid = test_fork();
		if (pid == 0) {
			close(tmp_pipe[1]);
			close(tmp_pipe_sub[0]);

			setpgid(0, 0);

			close(tmp_pipe_sub[1]);
			test_waitsig();

			if (getsid(0) != getppid())
				exit(1);
			if (getpgid(0) != getpid())
				exit(1);

			exit(0);
		}
		close(tmp_pipe_sub[1]);

		read(tmp_pipe_sub[0], &stat, 1);
		close(tmp_pipe_sub[0]);

		close(tmp_pipe[1]);

		test_waitsig();

		if (getpid() != getsid(0))
			exit(1);

		if (getpid() != getpgid(0))
			exit(2);

		kill(pid, SIGTERM);
		if (waitpid(pid, &stat, 0) < 0) {
			err("Unable to wait P2 %d", pid);
			exit(3);
		} else if (!WIFEXITED(stat) || WEXITSTATUS(stat)) {
			err("P2 stat %d/%d/%d/%d", WIFEXITED(stat), WEXITSTATUS(stat),
							WIFSIGNALED(stat), WTERMSIG(stat));
			exit(3);
		}

		exit(0);
	}
	close(tmp_pipe[1]);
	syncfd[1] = tmp_pipe[0];

	read(syncfd[0], &stat, 1);
	close(syncfd[0]);
	read(syncfd[1], &stat, 1);
	close(syncfd[1]);

	test_daemon();
	test_waitsig();

	for (i = 0; i < sizeof(pids) / sizeof(pids[0]); i++)
		kill(pids[i], SIGTERM);

	for (i = 0; i < sizeof(pids) / sizeof(pids[0]); i++) {
		if (waitpid(pids[i], &stat, 0) < 0) {
			err("Unable to wait %d", pids[i]);
			fail = 1;
		} else if (!WIFEXITED(stat) || WEXITSTATUS(stat)) {
			err("P%d stat %d/%d/%d/%d", i, WIFEXITED(stat), WEXITSTATUS(stat),
							WIFSIGNALED(stat), WTERMSIG(stat));
			fail = 1;
		}
	}

	if (fail)
		fail("Something failed");
	else
		pass();

	return 0;
}
