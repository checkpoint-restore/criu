#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "zdtmtst.h"

#define TASK_WAITER_INITIAL		0x0fffff

static long sys_gettid(void)
{
	return syscall(__NR_gettid);
}

void task_waiter_init(task_waiter_t *t)
{
	struct sockaddr_un addr;
	unsigned int addrlen;
	struct stat st;
	int sk;

	datagen((void *)&t->seed, sizeof(t->seed), NULL);
	t->seed = t->seed % TASK_WAITER_INITIAL;

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("Unable to create a socket");
		goto err;
	}

	if (fstat(sk, &st)) {
		pr_perror("Unable to stat a file descriptor");
		close(sk);
		goto err;
	}

	addr.sun_family = AF_UNIX;
	addrlen = snprintf(addr.sun_path, sizeof(addr.sun_path), "X/criu-zdtm-%lx", st.st_ino);
	addrlen += sizeof(addr.sun_family);

	addr.sun_path[0] = 0;
	if (bind(sk, &addr, addrlen)) {
		pr_perror("Unable to bind a socket");
		close(sk);
		goto err;
	}
	if (connect(sk, &addr, addrlen)) {
		pr_perror("Unable to connect a socket");
		close(sk);
		goto err;
	}

	t->sk = sk;
	return;
err:
	exit(1);
}

void task_waiter_fini(task_waiter_t *t)
{
	close(t->sk);
	t->sk = -1;
}

void task_waiter_wait4(task_waiter_t *t, unsigned int lockid)
{
	struct timespec req = { .tv_nsec = TASK_WAITER_INITIAL, };
	struct timespec rem = { };
	unsigned int v;

	for (;;) {
		if (recv(t->sk, &v, sizeof(v), MSG_PEEK) != sizeof(v))
			goto err;

		/*
		 * If we read a value not intended for us, say parent
		 * waits for specified child to complete among set of
		 * children, or we just have completed and wait for
		 * another lockid from a parent -- we need to write
		 * the value back and wait for some time before
		 * next attempt.
		 */
		if (v != lockid) {
			/*
			 * If we get a collision in access, lets sleep
			 * semi-random time magnitude to decrease probability
			 * of a new collision.
			 */
			nanosleep(&req, &rem);
			req.tv_nsec += t->seed;
		} else
			break;
	}
	if (recv(t->sk, &v, sizeof(v), 0) != sizeof(v))
		goto err;

	return;

err:
	pr_perror("task_waiter_wait4 failed");
	exit(errno);
}

void task_waiter_complete(task_waiter_t *t, unsigned int lockid)
{
	if (write(t->sk, &lockid, sizeof(lockid)) != sizeof(lockid)) {
		pr_perror("task_waiter_complete failed");
		exit(1);
	}
}

void task_waiter_complete_current(task_waiter_t *t)
{
	return task_waiter_complete(t, (int)sys_gettid());
}
