#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <time.h>

#include "zdtmtst.h"

#define TASK_WAITER_INITIAL		0x0fffff

static long sys_gettid(void)
{
	return syscall(__NR_gettid);
}

void task_waiter_init(task_waiter_t *t)
{
	datagen((void *)&t->seed, sizeof(t->seed), NULL);
	t->seed = t->seed % TASK_WAITER_INITIAL;

	if (pipe(t->pipes)) {
		pr_perror("task_waiter_init failed");
		exit(1);
	}
}

void task_waiter_fini(task_waiter_t *t)
{
	close(t->pipes[0]);
	close(t->pipes[1]);
}

void task_waiter_wait4(task_waiter_t *t, unsigned int lockid)
{
	struct timespec req = { .tv_nsec = TASK_WAITER_INITIAL, };
	struct timespec rem = { };
	unsigned int v;

	for (;;) {
		if (read(t->pipes[0], &v, sizeof(v)) != sizeof(v))
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
			if (write(t->pipes[1], &v, sizeof(v)) != sizeof(v))
				goto err;
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

	return;

err:
	pr_perror("task_waiter_wait4 failed");
	exit(errno);
}

void task_waiter_complete(task_waiter_t *t, unsigned int lockid)
{
	if (write(t->pipes[1], &lockid, sizeof(lockid)) != sizeof(lockid)) {
		pr_perror("task_waiter_complete failed");
		exit(1);
	}
}

void task_waiter_complete_current(task_waiter_t *t)
{
	return task_waiter_complete(t, (int)sys_gettid());
}
