#define _GNU_SOURCE
#include "criu.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
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

static pid_t start_child(bool new_userns)
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
		if (prctl(PR_SET_PDEATHSIG, SIGUSR1))
			_exit(1);
		if (new_userns && unshare(CLONE_NEWUSER))
			_exit(1);
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		if (write(ready[1], "R", 1) != 1)
			_exit(1);
		close(ready[1]);
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

	pid = start_child(false);
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

	pid = start_child(true);
	if (pid < 0)
		return 1;
	{
		char ns_file[PATH_MAX];

		snprintf(ns_file, sizeof(ns_file), "/proc/%d/ns/user", pid);
		init_criu("restore-unmapped-userns.log");
		if (criu_join_ns_add("user", ns_file, "0,0")) {
			kill(pid, SIGKILL);
			waitpid(pid, NULL, 0);
			return 1;
		}
		ret = criu_restore_child();
	}
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	if (ret != -EBADE) {
		fprintf(stderr, "restore into unmapped userns returned %d, expected %d\n", ret, -EBADE);
		if (ret > 0) {
			kill(ret, SIGKILL);
			waitpid(ret, NULL, 0);
		}
		return 1;
	}
	errno = 0;
	if (waitpid(-1, NULL, WNOHANG) != -1 || errno != ECHILD) {
		fprintf(stderr, "failed restore left a user namespace helper child behind\n");
		return 1;
	}

	init_criu("restore-sibling.log");
	if (criu_join_ns_add("user", "/proc/self/ns/user", NULL)) {
		fprintf(stderr, "libcriu rejected valid userns join options before RPC\n");
		return 1;
	}

	ret = criu_restore_child();
	if (ret <= 0) {
		fprintf(stderr, "restore-sibling with joined userns failed: %d\n", ret);
		return 1;
	}
	pid = ret;
	if (waitpid(pid, NULL, WNOHANG) != 0) {
		fprintf(stderr, "restored root died when the CRIU worker exited\n");
		return 1;
	}
	kill(pid, SIGKILL);
	if (waitpid(pid, NULL, 0) != pid) {
		perror("restored root is not a child of the RPC caller");
		return 1;
	}
	errno = 0;
	if (waitpid(-1, NULL, WNOHANG) != -1 || errno != ECHILD) {
		fprintf(stderr, "restore left a user namespace helper child behind\n");
		return 1;
	}

	return 0;
}
