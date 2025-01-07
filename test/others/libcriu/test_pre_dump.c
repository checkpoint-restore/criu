#include "criu.h"
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lib.h"

static int wdir_fd, cur_imgdir = -1;

static int stop = 0;
static void sh(int sig)
{
	stop = 1;
}

static void open_imgdir(void)
{
	char p[10];
	static int id = 0;

	if (id > 0) {
		sprintf(p, "../dir-%d", id);
		criu_set_parent_images(p);
	}
	if (cur_imgdir != -1)
		close(cur_imgdir);
	sprintf(p, "dir-%d", ++id);
	mkdirat(wdir_fd, p, 0700);
	cur_imgdir = openat(wdir_fd, p, O_DIRECTORY);
	criu_set_images_dir_fd(cur_imgdir);
}

int main(int argc, char **argv)
{
	int pid, ret, p[2];

	wdir_fd = open(argv[2], O_DIRECTORY);
	if (wdir_fd < 0) {
		perror("Can't open wdir");
		return 1;
	}

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
		if (signal(SIGUSR1, sh) == SIG_ERR)
			exit(1);

		close(0);
		close(1);
		close(2);
		close(p[0]);

		ret = SUCC_ECODE;
		write(p[1], &ret, sizeof(ret));
		close(p[1]);

		while (!stop)
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
	criu_set_track_mem(true);

	open_imgdir();
	ret = criu_pre_dump();
	if (ret < 0) {
		what_err_ret_mean(ret);
		kill(pid, SIGKILL);
		goto err;
	}

	printf("   `- Pre Dump 1 succeeded\n");

	open_imgdir();
	ret = criu_pre_dump();
	if (ret < 0) {
		what_err_ret_mean(ret);
		kill(pid, SIGKILL);
		goto err;
	}

	printf("   `- Pre Dump 2 succeeded\n");

	open_imgdir();
	ret = criu_dump();
	if (ret < 0) {
		what_err_ret_mean(ret);
		kill(pid, SIGKILL);
		goto err;
	}

	printf("   `- Final Dump succeeded\n");
	waitpid(pid, NULL, 0);

	printf("--- Restore ---\n");
	criu_init_opts();
	criu_set_log_level(CRIU_LOG_DEBUG);
	criu_set_log_file("restore.log");
	criu_set_images_dir_fd(cur_imgdir);

	pid = criu_restore_child();
	if (pid <= 0) {
		what_err_ret_mean(pid);
		return -1;
	}

	printf("   `- Restore returned pid %d\n", pid);
	kill(pid, SIGUSR1);
err:
	if (waitpid(pid, &ret, 0) < 0) {
		perror("   Can't wait kid");
		return -1;
	}

	return chk_exit(ret, SUCC_ECODE);
}
