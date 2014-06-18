#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc    = "Check dumpable flag handling (non-dumpable case)";
const char *test_author = "Filipe Brandenburger <filbranden@google.com>";

int dumpable_server() {
	char buf[256];
	int ret;

	for (;;) {
		ret = read(0, buf, sizeof(buf));
		if (ret == 0)
			break;
		ret = snprintf(buf, sizeof(buf), "DUMPABLE:%d\n", prctl(PR_GET_DUMPABLE));
		write(1, buf, ret);
	}
	return 0;
}

int get_dumpable_from_pipes(int pipe_input, int pipe_output) {
	char buf[256];
	int len;
	long value;
	char *endptr = NULL;

	/* input and output are from the child's point of view. */

	write(pipe_input, "GET\n", 4);
	len = read(pipe_output, buf, sizeof(buf));
	if (len < 0) {
		err("error in parent reading from pipe");
		return -1;
	}

	if (memcmp(buf, "DUMPABLE:", 9) != 0) {
		err("child returned [%s]", buf);
		return -1;
	}

	value = strtol(&buf[9], &endptr, 10);
	if (!endptr || *endptr != '\n' || endptr != buf + len - 1) {
		err("child returned [%s]", buf);
		return -1;
	}

	return (int)value;
}


int main(int argc, char **argv)
{
	int pipe_input[2];
	int pipe_output[2];
	int save_dumpable;
	int dumpable;
	int ret;
	pid_t pid;
	pid_t waited;
	int status;

	/*
	 * Check if we are being re-executed to spawn the dumpable server. This
	 * re-execution is what essentially causes the dumpable flag to be
	 * cleared since we have execute but not read permissions to the
	 * binary.
	 */
	if (getenv("DUMPABLE_SERVER"))
		return dumpable_server();

	/*
	 * Otherwise, do normal startup and spawn a dumpable server. While we
	 * are still running as root, chmod() the binary to give it execute but
	 * not read permissions, that way when we execv() it as a non-root user
	 * the kernel will drop our dumpable flag and reset it to the value in
	 * /proc/sys/fs/suid_dumpable.
	 */
	ret = chmod(argv[0], 0111);
	if (ret < 0) {
		err("error chmodding %s", argv[0]);
		return 1;
	}

	test_init(argc, argv);

	ret = pipe(pipe_input);
	if (ret < 0) {
		err("error creating input pipe");
		return 1;
	}

	ret = pipe(pipe_output);
	if (ret < 0) {
		err("error creating output pipe");
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		err("error forking the dumpable server");
		return 1;
	}

	if (pid == 0) {
		/*
		 * Child process will execv() the dumpable server. Start by
		 * reopening stdin and stdout to use the pipes, then set the
		 * environment variable and execv() the same binary.
		 */
		close(0);
		close(1);

		ret = dup2(pipe_input[0], 0);
		if (ret < 0) {
			err("could not dup2 pipe into child's stdin");
			return 1;
		}

		ret = dup2(pipe_output[1], 1);
		if (ret < 0) {
			err("could not dup2 pipe into child's stdout");
			return 1;
		}

		close(pipe_output[0]);
		close(pipe_output[1]);
		close(pipe_input[0]);
		close(pipe_input[1]);

		ret = setenv("DUMPABLE_SERVER", "yes", 1);
		if (ret < 0) {
			err("could not set the DUMPABLE_SERVER env variable");
			return 1;
		}

		ret = execl(argv[0], "dumpable_server", NULL);
		err("could not execv %s as a dumpable_server", argv[0]);
		return 1;
	}

	/*
	 * Parent process, write to the pipe_input socket to ask the server
	 * child to tell us what its dumpable flag value is on its side.
	 */
	close(pipe_input[0]);
	close(pipe_output[1]);

	save_dumpable = get_dumpable_from_pipes(pipe_input[1], pipe_output[0]);
	if (save_dumpable < 0) return 1;
#ifdef DEBUG
	test_msg("DEBUG: before dump: dumpable=%d\n", save_dumpable);
#endif

	/* Wait for dump and restore. */
	test_daemon();
	test_waitsig();

	dumpable = get_dumpable_from_pipes(pipe_input[1], pipe_output[0]);
	if (dumpable < 0) return 1;
#ifdef DEBUG
	test_msg("DEBUG: after restore: dumpable=%d\n", dumpable);
#endif

	if (dumpable != save_dumpable) {
		errno = 0;
		fail("dumpable flag was not preserved over migration");
		return 1;
	}

	/* Closing the pipes will terminate the child server. */
	close(pipe_input[1]);
	close(pipe_output[0]);

	waited = wait(&status);
	if (waited < 0) {
		err("error calling wait on the child");
		return 1;
	}
	errno = 0;
	if (waited != pid) {
		err("waited pid %d did not match child pid %d",
		    waited, pid);
		return 1;
	}
	if (!WIFEXITED(status)) {
		err("child dumpable server returned abnormally with status=%d",
		    status);
		return 1;
	}
	if (WEXITSTATUS(status) != 0) {
		err("child dumpable server returned rc=%d",
		    WEXITSTATUS(status));
		return 1;
	}

	pass();
	return 0;
}
