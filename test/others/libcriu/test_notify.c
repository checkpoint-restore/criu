#include "criu.h"
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "lib.h"

#define SUCC_ECODE 42

static int actions_called = 0;
static int notify(char *action, criu_notify_arg_t na)
{
	printf("ACTION: %s\n", action);
	actions_called++;
	return 0;
}

int main(int argc, char **argv)
{
	int pid, ret, fd, p[2];

	printf("--- Start loop ---\n");
	pipe(p);
	pid = fork();
	if (pid < 0) {
		perror("Can't");
		return -1;
	}

	if (!pid) {
		printf("   `- loop: initializing\n");
		if (setsid() < 0)
			exit(1);

		close(0);
		close(1);
		close(2);
		close(p[0]);

		ret = SUCC_ECODE;
		write(p[1], &ret, sizeof(ret));
		close(p[1]);

		while (1)
			sleep(1);

		exit(SUCC_ECODE);
	}

	close(p[1]);

	/* Wait for kid to start */
	ret = -1;
	read(p[0], &ret, sizeof(ret));
	if (ret != SUCC_ECODE) {
		printf("Error starting loop\n");
		goto err;
	}

	/* Wait for pipe to get closed, then dump */
	read(p[0], &ret, 1);
	close(p[0]);

	printf("--- Dump loop ---\n");
	criu_init_opts();
	criu_set_service_binary(argv[1]);
	criu_set_pid(pid);
	criu_set_log_file("dump.log");
	criu_set_log_level(CRIU_LOG_DEBUG);
	criu_set_notify_cb(notify);
	fd = open(argv[2], O_DIRECTORY);
	criu_set_images_dir_fd(fd);

	ret = criu_dump();
	if (ret < 0) {
		what_err_ret_mean(ret);
		kill(pid, SIGKILL);
		goto err;
	}

	printf("   `- Dump succeeded\n");
	ret = 0;
err:
	waitpid(pid, NULL, 0);
	if (ret || !actions_called) {
		printf("FAIL (%d/%d)\n", ret, actions_called);
		return 1;
	}

	printf("   `- Success (%d actions)\n", actions_called);
	return 0;
}
