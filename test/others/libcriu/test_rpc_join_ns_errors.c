#include "criu.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lib.h"

static int dir_fd;
static char *criu_bin;
static char *image_dir;

static void init_criu(const char *log_file)
{
	criu_init_opts();
	criu_set_service_binary(criu_bin);
	criu_set_images_dir_fd(dir_fd);
	criu_set_log_level(CRIU_LOG_DEBUG);
	criu_set_log_file(log_file);
}

static pid_t start_child(void)
{
	int ready[2];
	pid_t pid;
	char c;

	if (pipe(ready)) {
		perror("pipe");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (pid == 0) {
		close(ready[0]);
		if (setsid() < 0)
			_exit(1);
		if (write(ready[1], "R", 1) != 1)
			_exit(1);
		while (1)
			pause();
	}

	close(ready[1]);
	if (read(ready[0], &c, 1) != 1) {
		perror("read ready");
		kill(pid, SIGKILL);
		return -1;
	}
	close(ready[0]);

	return pid;
}

int main(int argc, char **argv)
{
	pid_t pid;
	int ret;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s CRIU-BIN IMAGE-DIR\n", argv[0]);
		return 1;
	}

	criu_bin = argv[1];
	image_dir = argv[2];
	dir_fd = open(argv[2], O_DIRECTORY);
	if (dir_fd < 0) {
		perror("Can't open images dir");
		return 1;
	}

	pid = start_child();
	if (pid < 0)
		return 1;

	init_criu("dump.log");
	criu_set_pid(pid);
	ret = criu_dump();
	if (ret) {
		what_err_ret_mean(ret);
		kill(pid, SIGKILL);
		return 1;
	}
	{
		char inventory[PATH_MAX];

		snprintf(inventory, sizeof(inventory), "%s/inventory.img", image_dir);
		if (access(inventory, F_OK)) {
			perror("dump did not create inventory.img");
			kill(pid, SIGKILL);
			return 1;
		}
	}

	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);

	init_criu("restore.log");
	if (criu_join_ns_add("user", "/proc/self/ns/user", "not-a-uid,0")) {
		fprintf(stderr, "libcriu rejected join-ns before RPC\n");
		return 1;
	}

	ret = criu_restore_child();
	if (ret > 0) {
		fprintf(stderr, "restore unexpectedly accepted invalid userns join options\n");
		kill(ret, SIGKILL);
		waitpid(ret, NULL, 0);
		return 1;
	}

	if (ret != -EBADE) {
		fprintf(stderr, "restore failed with %d, expected %d\n", ret, -EBADE);
		return 1;
	}

	init_criu("restore-sibling.log");
	if (criu_join_ns_add("user", "/proc/self/ns/user", NULL)) {
		fprintf(stderr, "libcriu rejected valid userns join options before RPC\n");
		return 1;
	}

	ret = criu_restore_child();
	if (ret > 0) {
		fprintf(stderr, "restore-sibling unexpectedly accepted joined userns\n");
		kill(ret, SIGKILL);
		waitpid(ret, NULL, 0);
		return 1;
	}

	if (ret != -EBADE) {
		fprintf(stderr, "restore-sibling failed with %d, expected %d\n", ret, -EBADE);
		return 1;
	}

	return 0;
}
