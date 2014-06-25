#include "criu.h"
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

static void what_err_ret_mean(ret)
{
	/* NOTE: errno is set by libcriu */
	switch (ret) {
	case -EBADE:
		perror("RPC has returned fail");
		break;
	case -ECONNREFUSED:
		perror("Unable to connect to CRIU");
		break;
	case -ECOMM:
		perror("Unable to send/recv msg to/from CRIU");
		break;
	case -EINVAL:
		perror("CRIU doesn't support this type of request."
		       "You should probably update CRIU");
		break;
	case -EBADMSG:
		perror("Unexpected response from CRIU."
		       "You should probably update CRIU");
		break;
	default:
		perror("Unknown error type code."
		       "You should probably update CRIU");
	}
}

static inline int chk_exit(int status, int want)
{
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) == want) {
			printf("   `- Success\n");
			return 0;
		}

		printf("   `- FAIL (exit %d)\n", WEXITSTATUS(status));
	} else if (WIFSIGNALED(status))
		printf("   `- FAIL (die %d)\n", WTERMSIG(status));
	else
		printf("   `- FAIL (%#x)\n", status);

	return 1;
}

#define SUCC_DUMP_ECODE	41
#define SUCC_RSTR_ECODE	43

int main(int argc, char *argv[])
{
	int ret, fd, pid;

	fd = open(argv[2], O_DIRECTORY);
	if (fd < 0) {
		perror("Can't open images dir");
		return 1;
	}

	criu_init_opts();
	criu_set_service_address(argv[1]);
	criu_set_images_dir_fd(fd);
	criu_set_log_level(4);

	printf("--- Start child ---\n");
	pid = fork();
	if (pid < 0) {
		perror("Can't");
		return 1;
	}

	if (!pid) {
		/*
		 * Child process -- dump itself, then
		 * parent would restore us.
		 */

		close(0);
		close(1);
		close(2);
		if (setsid() < 0)
			exit(1);

		criu_set_log_file("dump.log");
		criu_set_leave_running(true);
		ret = criu_dump();
		if (ret < 0) {
			what_err_ret_mean(ret);
			exit(1);
		}

		if (ret == 0)
			ret = SUCC_DUMP_ECODE; /* dumped OK */
		else if (ret == 1)
			ret = SUCC_RSTR_ECODE; /* restored OK */
		else
			ret = 1;

		exit(ret);
	}

	printf("--- Wait for self-dump ---\n");
	if (waitpid(pid, &ret, 0) < 0) {
		perror("Can't wait child");
		goto errk;
	}

	if (chk_exit(ret, SUCC_DUMP_ECODE))
		goto errk;

	printf("--- Restore ---\n");
	criu_set_log_file("restore.log");

	pid = criu_restore_child();
	if (pid <= 0) {
		what_err_ret_mean(pid);
		goto err;
	}

	if (waitpid(pid, &ret, 0) < 0) {
		perror("Can't wait rchild");
		goto errk;
	}

	return chk_exit(ret, SUCC_RSTR_ECODE);

errk:
	kill(pid, SIGKILL);
err:
	return 1;

}
