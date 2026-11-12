#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Socketpair held by a task and a child whose pid is below the task's";
const char *test_author = "Alex Xu <ax2155@columbia.edu>";

#define SK_DATA "packet"
#define NR_BURN 64

/* Rewind the pid allocator, so that the next fork gets a low pid. */
static int rewind_pids(void)
{
	int fd, len;
	char buf[32];

	fd = open("/proc/sys/kernel/ns_last_pid", O_WRONLY);
	if (fd < 0) {
		pr_perror("Failed to open ns_last_pid");
		return -1;
	}
	len = snprintf(buf, sizeof(buf), "%d", 1);
	if (write(fd, buf, len) != len) {
		pr_perror("Failed to write ns_last_pid");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int exchange(int sk)
{
	char buf[64];

	memset(buf, 0, sizeof(buf));
	if (write(sk, SK_DATA, sizeof(SK_DATA)) != sizeof(SK_DATA)) {
		pr_perror("write");
		return -1;
	}
	if (read(sk, buf, sizeof(buf)) != sizeof(SK_DATA)) {
		pr_perror("read");
		return -1;
	}
	if (strcmp(buf, SK_DATA)) {
		pr_err("data corrupted\n");
		return -1;
	}
	return 0;
}

/* Echoes on the socket until it is closed. */
static void child(int sk)
{
	char buf[64];
	int n;

	while ((n = read(sk, buf, sizeof(buf))) > 0)
		if (write(sk, buf, n) != n)
			_exit(1);
	_exit(n < 0);
}

/*
 * Holds both ends of the pair, the child only one. Reports on the control
 * pipe: 'r' when ready, then waits for 'g' and reports 'p' or 'f'.
 */
static void parent(int ctl_r, int ctl_w)
{
	int sk[2], status;
	pid_t pid;
	char c;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk) == -1) {
		pr_perror("socketpair");
		_exit(1);
	}

	if (rewind_pids())
		_exit(1);

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		_exit(1);
	}
	if (pid == 0) {
		close(sk[0]);
		close(ctl_r);
		close(ctl_w);
		child(sk[1]);
	}
	if (pid > getpid()) {
		pr_err("child %d is above the parent %d, the pid order is not inverted\n", pid, getpid());
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		_exit(1);
	}

	if (exchange(sk[0]))
		_exit(1);

	c = 'r';
	if (write(ctl_w, &c, 1) != 1 || read(ctl_r, &c, 1) != 1 || c != 'g')
		_exit(1);

	c = exchange(sk[0]) ? 'f' : 'p';
	if (write(ctl_w, &c, 1) != 1)
		_exit(1);

	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	_exit(0);
}

int main(int argc, char *argv[])
{
	int to_parent[2], from_parent[2], status, i;
	pid_t pid;
	char c;

	test_init(argc, argv);

	/* Use up some pids, so that the parent's is well above the lowest free ones. */
	for (i = 0; i < NR_BURN; i++) {
		pid = fork();
		if (pid < 0) {
			pr_perror("fork");
			exit(1);
		}
		if (pid == 0)
			_exit(0);
		waitpid(pid, &status, 0);
	}

	if (pipe(to_parent) || pipe(from_parent)) {
		pr_perror("pipe");
		exit(1);
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		exit(1);
	}
	if (pid == 0) {
		close(to_parent[1]);
		close(from_parent[0]);
		parent(to_parent[0], from_parent[1]);
	}
	close(to_parent[0]);
	close(from_parent[1]);

	if (read(from_parent[0], &c, 1) != 1 || c != 'r') {
		pr_err("the parent did not get ready\n");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	c = 'g';
	if (write(to_parent[1], &c, 1) != 1 || read(from_parent[0], &c, 1) != 1) {
		fail("the parent is gone");
		goto out;
	}
	if (c != 'p') {
		fail("the pair does not work after restore");
		goto out;
	}

	pass();
out:
	waitpid(pid, &status, 0);
	return 0;
}
