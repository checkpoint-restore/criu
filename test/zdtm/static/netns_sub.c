#include <sched.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>

#include "zdtmtst.h"

const char *test_doc	= "Check dump and restore a few network namespaces";

static int fill_name(int nsid, struct sockaddr_un *name)
{
	int len;

	name->sun_family = AF_LOCAL;
	snprintf(name->sun_path, 108, "X/zdtm/static/netns_sub-%d", nsid);
	len = SUN_LEN(name);
	name->sun_path[0] = 0;

	return len;
}

static int create_socket(int nsid)
{
	struct sockaddr_un name;
	int len, sk;

	len = fill_name(nsid, &name);

	sk = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("socket");
		return -1;
	}

	if (bind(sk, (struct sockaddr *) &name, len) < 0) {
		pr_perror("bind");
		close(sk);
		return -1;
	}

	return sk;
}

static int check_socket(int nsid, bool success)
{
	struct sockaddr_un name;
	int len, sk;

	len = fill_name(nsid, &name);

	sk = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("socket");
		return -1;
	}

	if (connect(sk, (struct sockaddr *) &name, len) < 0) {
		if (!success && errno == ECONNREFUSED)
			return 0;
		pr_perror("connect to %d", nsid);
		close(sk);
		return -1;
	}
	close(sk);

	if (!success) {
		pr_err("A sokcet is able to connect to %d\n", nsid);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	task_waiter_t lock;
	pid_t pid1, pid2, pid3, pid0 = getpid();
	int status = -1, sk;

	test_init(argc, argv);
	task_waiter_init(&lock);

	sk = create_socket(0);
	if (sk < 0)
		return 1;

	pid1 = fork();
	if (pid1 < 0) {
		pr_perror("fork");
		return -1;
	}
	if (pid1 == 0) {
		close(sk);
		unshare(CLONE_NEWNET);
		sk = create_socket(1);
		if (sk < 0)
			return 1;

		pid3 = fork();
		if (pid3 < 0) {
			pr_perror("fork");
			return 1;
		}
		if (pid3 == 0) {
			char ns[] = "/proc/0123456789/ns/net";
			int fd;

			snprintf(ns, sizeof(ns), "/proc/%d/ns/net", pid0);
			fd = open(ns, O_RDONLY);
			if (fd < 0)
				return 1;

			if (setns(fd, 0))
				return 1;
			close(fd);

			task_waiter_complete(&lock, 3);
			test_waitsig();

			if (check_socket(0, true))
				return 1;
			if (check_socket(2, false))
				return 1;
			if (check_socket(1, false))
				return 1;

			return 0;
		}
		/* This socket will be alive in the 3 process */
		close(sk);

		task_waiter_complete(&lock, 1);
		test_waitsig();

		if (check_socket(1, true))
			return 1;

		kill(pid3, SIGTERM);
		waitpid(pid3, &status, 0);
		if (status) {
			fail();
			return 1;
		}

		return 0;
	}
	pid2 = fork();
	if (pid2 < 0) {
		pr_perror("fork");
		return -1;
	}
	if (pid2 == 0) {
		unshare(CLONE_NEWNET);
		sk = create_socket(2);
		if (sk < 0)
			return 1;
		task_waiter_complete(&lock, 2);

		test_waitsig();

		if (check_socket(0, false))
			return 1;
		if (check_socket(1, false))
			return 1;
		if (check_socket(2, true))
			return 1;

		return 0;
	}
	close(sk);
	task_waiter_wait4(&lock, 1);
	task_waiter_wait4(&lock, 2);
	task_waiter_wait4(&lock, 3);

	test_daemon();
	test_waitsig();

	kill(pid1, SIGTERM);
	waitpid(pid1, &status, 0);
	if (status) {
		fail();
		return 1;
	}
	kill(pid2, SIGTERM);
	status = -1;
	waitpid(pid2, &status, 0);
	if (status) {
		fail();
		return 1;
	}
	pass();
	return 0;
}
