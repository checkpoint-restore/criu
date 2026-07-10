#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>

#include "zdtmtst.h"

const char *test_doc = "Check dump/restore of a process tree with a child PID namespace";
const char *test_author = "Nidhish Gajjar <hacker@scigic.com>";

int main(int argc, char **argv)
{
	int pipe_ready[2], pipe_go[2], pipe_result[2];
	int status;
	pid_t child, ret;
	char buf;

	test_init(argc, argv);

	if (pipe(pipe_ready) || pipe(pipe_go) || pipe(pipe_result)) {
		pr_perror("pipe");
		return 1;
	}

	/*
	 * Create a new PID namespace. The next fork()'d child
	 * will be PID 1 inside this new namespace.
	 */
	if (unshare(CLONE_NEWPID)) {
		pr_perror("unshare(CLONE_NEWPID)");
		return 1;
	}

	child = fork();
	if (child < 0) {
		pr_perror("fork child");
		return 1;
	}

	if (child == 0) {
		/*
		 * Child: PID 1 inside the new PID namespace.
		 */
		pid_t my_pid;
		char res = '0';

		close(pipe_ready[0]);
		close(pipe_go[1]);
		close(pipe_result[0]);

		/*
		 * Create a new session inside the child PID namespace.
		 * Without this, getsid() returns 0 because the inherited
		 * session leader lives in the parent namespace and is not
		 * visible here.
		 */
		if (setsid() < 0) {
			pr_perror("setsid");
			_exit(1);
		}

		my_pid = getpid();
		if (my_pid != 1) {
			fprintf(stderr, "Child expected PID 1 before C/R, got %d\n", my_pid);
			_exit(1);
		}

		/* Signal parent we're ready */
		write(pipe_ready[1], "R", 1);
		close(pipe_ready[1]);

		/*
		 * Wait for parent to tell us to check PID.
		 * Dump/restore happens while we're blocked here.
		 */
		if (read(pipe_go[0], &buf, 1) != 1) {
			_exit(1);
		}
		close(pipe_go[0]);

		/* After restore: verify PID is still 1 inside our namespace */
		my_pid = getpid();
		if (my_pid != 1) {
			fprintf(stderr, "Child expected PID 1 after C/R, got %d\n", my_pid);
			res = '1';
		}

		write(pipe_result[1], &res, 1);
		close(pipe_result[1]);
		_exit(0);
	}

	/* Parent: in the original PID namespace */
	close(pipe_ready[1]);
	close(pipe_go[0]);
	close(pipe_result[1]);

	/* Wait for child to be ready */
	if (read(pipe_ready[0], &buf, 1) != 1 || buf != 'R') {
		pr_perror("child not ready");
		kill(child, SIGKILL);
		return 1;
	}
	close(pipe_ready[0]);

	test_msg("Child host PID: %d (namespace PID should be 1)\n", child);

	/* Checkpoint happens here */
	test_daemon();
	test_waitsig();

	/*
	 * After restore: tell child to verify its PID and report.
	 * Use pipe instead of kill() since host PID may change.
	 */
	write(pipe_go[1], "G", 1);
	close(pipe_go[1]);

	/* Read result from child */
	if (read(pipe_result[0], &buf, 1) != 1) {
		fail("Failed to read result from child");
		return 1;
	}
	close(pipe_result[0]);

	ret = waitpid(child, &status, 0);
	if (ret < 0 && errno == ECHILD) {
		/*
		 * After restore, the host PID may have changed.
		 * Wait for any child instead.
		 */
		ret = waitpid(-1, &status, 0);
	}

	if (ret < 0) {
		fail("waitpid: %m");
		return 1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fail("Child exit status: exited=%d code=%d signaled=%d sig=%d",
		     WIFEXITED(status), WEXITSTATUS(status),
		     WIFSIGNALED(status), WTERMSIG(status));
		return 1;
	}

	if (buf != '0') {
		fail("Child PID was not preserved across dump/restore");
		return 1;
	}

	pass();
	return 0;
}
