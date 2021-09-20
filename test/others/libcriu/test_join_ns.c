#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "criu.h"
#include "lib.h"

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080 /* New time namespace */
#endif

static pid_t child_pid;
static int pipefd[2];

static int dir_fd;
static char *criu_bin;

static bool timens_support(void)
{
	return access("/proc/self/ns/time", F_OK) == 0;
}

static void create_child_process(void)
{
	pid_t pid = fork();
	if (pid < 0) {
		perror("fork failed");
		exit(1);
	}

	if (pid == 0) {
		if (setsid() < 0)
			exit(1);
		pid = getpid();
		write(pipefd[1], &pid, sizeof(pid));
		while (1)
			sleep(1);
	}
}

static void unshare_namespaces(void)
{
	int flags = CLONE_NEWIPC | CLONE_NEWUTS;
	if (unshare(flags)) {
		perror("Can't unshare namespaces");
		exit(1);
	}

	if (timens_support() && unshare(CLONE_NEWTIME)) {
		perror("unshare(CLONE_NEWTIME) failed");
		exit(1);
	}
}

static void init_criu_request(void)
{
	if (criu_init_opts()) {
		fprintf(stderr, "failed to initialise request options\n");
		exit(1);
	}
	criu_set_service_binary(criu_bin);
	criu_set_images_dir_fd(dir_fd);
	criu_set_log_level(CRIU_LOG_DEBUG);
}

static void checkpoint_test(void)
{
	int pid, ret;

	pipe(pipefd);

	pid = fork();
	if (pid < 0) {
		perror("fork failed");
		exit(1);
	}

	if (pid == 0) {
		unshare_namespaces();
		/* Close unused read end */
		close(pipefd[0]);
		create_child_process();
		exit(0);
	}

	/* Close unused write end */
	close(pipefd[1]);
	/* Read child PID */
	read(pipefd[0], &child_pid, sizeof(child_pid));

	init_criu_request();
	criu_set_log_file("dump.log");
	criu_set_pid(child_pid);

	ret = criu_dump();
	if (ret < 0) {
		what_err_ret_mean(ret);
		exit(1);
	}

	kill(pid, SIGKILL);
	if (waitpid(pid, NULL, 0) < 0) {
		perror("Can't wait pid");
		exit(1);
	}
}

static void join_ns(const char *ns, pid_t pid)
{
	char ns_file[PATH_MAX];
	snprintf(ns_file, sizeof(ns_file), "/proc/%d/ns/%s", pid, ns);
	criu_join_ns_add(ns, ns_file, NULL);
}

static pid_t create_namespaces(void)
{
	pid_t pid = fork();
	if (pid < 0) {
		perror("fork failed");
		exit(1);
	}

	if (pid == 0) {
		unshare_namespaces();
		while (1)
			sleep(1);
	}

	return pid;
}

static int get_ns_ino(pid_t pid, const char *nsname, ino_t *ino)
{
	struct stat st;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, nsname);
	printf("Stat %s\n", path);
	if (stat(path, &st))
		return -errno;
	*ino = st.st_ino;

	return 0;
}

static int compare_namespace(const char *nsname, pid_t parent_pid)
{
	ino_t child_ns_ino, parent_ns_ino;

	printf("Compare %s ns for %d and %d\n", nsname, child_pid, parent_pid);

	if (get_ns_ino(child_pid, nsname, &child_ns_ino)) {
		perror("Failed to get child ns inode");
		return -1;
	}

	if (get_ns_ino(parent_pid, nsname, &parent_ns_ino)) {
		perror("Failed to get parent ns inode");
		return -1;
	}

	return child_ns_ino != parent_ns_ino;
}

static int restore_test(void)
{
	int ret;
	pid_t parent_pid = create_namespaces();

	init_criu_request();
	criu_set_log_file("restore.log");

	join_ns("ipc", parent_pid);
	join_ns("uts", parent_pid);
	if (timens_support())
		join_ns("time", parent_pid);

	ret = criu_restore_child();
	if (ret < 0) {
		what_err_ret_mean(ret);
		exit(1);
	}

	/* Verify that the child process has joined correct namespaces */

	if (compare_namespace("ipc", parent_pid)) {
		fprintf(stderr, "Error: IPC ns doesn't match\n");
		exit(1);
	}

	if (compare_namespace("uts", parent_pid)) {
		fprintf(stderr, "Error: UTS ns doesn't match\n");
		exit(1);
	}

	if (timens_support() && compare_namespace("time", parent_pid)) {
		fprintf(stderr, "Error: Time ns doesn't match\n");
		exit(1);
	}

	kill(child_pid, SIGKILL);
	if (waitpid(child_pid, NULL, 0) < 0) {
		perror("Can't wait child pid");
		exit(1);
	}

	kill(parent_pid, SIGKILL);
	if (waitpid(parent_pid, NULL, 0) < 0) {
		perror("Can't wait parent pid");
		exit(1);
	}

	return 0;
}

int main(int argc, char **argv)
{
	int exit_code;

	criu_bin = argv[1];
	dir_fd = open(argv[2], O_DIRECTORY);
	if (dir_fd < 0) {
		perror("Can't open images dir");
		return -1;
	}

	checkpoint_test();
	exit_code = restore_test();

	close(dir_fd);
	return exit_code;
}
