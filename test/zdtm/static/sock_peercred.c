#include <sched.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

#include "zdtmtst.h"

#define STACK_SIZE (1024 * 1024)
#define GID_INC 1
#define UID_INC 1

const char *test_doc    = "Check peercred of a unix socket remains the same";
const char *test_author = "Kirill Tkhai <ktkhai@virtuozzo.com>";

static int child_func(void *fd_p)
{
	int fd = (int)(unsigned long)fd_p;
	struct ucred ucred;
	socklen_t len;
	int sks[2];

	if (setgid(getgid() + GID_INC) != 0) {
		pr_perror("Can't setgid()");
		return 1;
	}

	if (setuid(getuid() + UID_INC) != 0) {
		pr_perror("Can't setuid()");
		return 1;
	}

	if (socketpair(PF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, sks) < 0) {
		pr_perror("Can't create socketpair");
		return 1;
	}

	len = sizeof(ucred);
	if (getsockopt(sks[0], SOL_SOCKET, SO_PEERCRED, &ucred, &len) < 0) {
		pr_perror("Can't getsockopt()");
		return 1;
	}

	if (ucred.pid != getpid() || ucred.uid != getuid() || ucred.gid != getgid()) {
		pr_perror("Wrong sockopts");
		return 1;
	}

	/* If sks[1] == fd, the below closes it, but we don't care */
	if (dup2(sks[0], fd) == -1) {
		pr_perror("Can't dup fd\n");
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ucred ucred;
	int fd, status;
	socklen_t len;
	char *stack;
	pid_t pid;
	int exit_code = 1;

	test_init(argc, argv);

	/*
	 * We do not know, which direction stack grows.
	 * So just allocate 2 * STACK_SIZE for stack and
	 * give clone() pointer to middle of this memory.
	 */
	stack = malloc(2 * STACK_SIZE);
	if (!stack) {
		pr_err("malloc\n");
		goto out;
	}

	/* Find unused fd */
	for (fd = 0; fd < INT_MAX; fd++) {
		if (fcntl(fd, F_GETFD) == -1 && errno == EBADF)
			break;
	}

	if (fd == INT_MAX) {
		pr_err("INT_MAX happens...\n");
		goto out;
	}

	pid = clone(child_func, stack + STACK_SIZE, CLONE_FILES|SIGCHLD, (void *)(unsigned long)fd);
	if (pid == -1) {
		pr_perror("clone");
		goto out;
	}

	if (wait(&status) == -1 || status) {
		pr_perror("wait error: status=%d\n", status);
		goto out;
	}

	test_daemon();
	test_waitsig();

	len = sizeof(ucred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) < 0) {
		fail("Can't getsockopt()");
		goto out;
	}

	if (ucred.pid != pid || ucred.gid != getuid() + UID_INC ||
			        ucred.gid != getgid() + GID_INC) {
		fail("Wrong pid, uid or gid\n");
		goto out;
	}

	pass();
	exit_code = 0;
 out:
	free(stack);
	return exit_code;
}
