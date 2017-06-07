#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc	= "Check that restorer for sockets is choosed right in dependence of net_ns->user_ns";
const char *test_author	= "Kirill Tkhai <ktkhai@virtuozzo.com>";

enum {
	FUTEX_INITIALIZED = 0,
	MAPS_SET,
	CHILD_PREPARED,
	POST_RESTORE_CHECK,
	EMERGENCY_ABORT,
};

futex_t *futex;

int write_map(pid_t pid, char *file, char *map)
{
	char path[PATH_MAX];
	int fd, ret;

	sprintf(path, "/proc/%d/%s", pid, file);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		fail("Can't open");
		return -1;
	}
	ret = write(fd, map, strlen(map));
	if (ret != strlen(map)) {
		fail("Can't write");
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

int child_fn(void *arg)
{
	int sk, orig_sk = (int)(long)arg;
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);

	if (getsockname(orig_sk, &addr, &len) < 0) {
		pr_perror("getsockname()");
		goto err;
	}
	futex_wait_while_lt(futex, MAPS_SET);
	if (futex_get(futex) == EMERGENCY_ABORT)
		return 1;

	if (setuid(0)) {
		pr_perror("Can't set uid");
		goto err;
	}
	if (setgid(0)) {
		pr_perror("Can't set gid");
		goto err;
	}

	futex_set_and_wake(futex, CHILD_PREPARED);
	futex_wait_while_lt(futex, POST_RESTORE_CHECK);

	sk = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("socket");
		goto err;
	}

	/* This must complete w/o errors, as orig_sk is from another net namespace */
	if (bind(sk, (struct sockaddr *)&addr, len) < 0) {
		pr_perror("bind");
		goto err;
	}

	return 0;
err:
	futex_set_and_wake(futex, EMERGENCY_ABORT);
	return 1;
}

int main(int argc, char **argv)
{
	struct sockaddr_un addr;
	int sk, len;
	int status;
	pid_t pid;

	test_init(argc, argv);
	futex = mmap(NULL, sizeof(*futex), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (futex == MAP_FAILED) {
		fail("mmap futex\n");
		return 1;
	}
	futex_init(futex);

	sk = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		fail("socket");
		return 1;
	}

	addr.sun_family = AF_UNIX;
	sprintf(addr.sun_path, "x/test-socket-name");
	len = SUN_LEN(&addr);
	*addr.sun_path = '\0';

	if (bind(sk, (struct sockaddr *)&addr, len) < 0) {
		fail("bind");
		return 1;
	}

	{
		char stack;
		pid = clone(child_fn, &stack - 256, CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWPID, (void *)(long)sk);
		if (pid == -1) {
			fail("clone");
			return 1;
		}
	}

	if (write_map(pid, "uid_map", "0 10 1") < 0 ||
	    write_map(pid, "gid_map", "0 12 1") < 0) {
		fail("write map");
		goto err;
	}

	futex_set_and_wake(futex, MAPS_SET);
	futex_wait_while_lt(futex, CHILD_PREPARED);

	close(sk);

	test_daemon();
	test_waitsig();

	futex_set_and_wake(futex, POST_RESTORE_CHECK);

	if (wait(&status) < 0 || WEXITSTATUS(status)) {
		fail("pid: status=%d\n", WEXITSTATUS(status));
		goto err;
	}

	pass();
	return 0;
err:
	futex_set_and_wake(futex, EMERGENCY_ABORT);
	wait(&status);
	return 1;
}
