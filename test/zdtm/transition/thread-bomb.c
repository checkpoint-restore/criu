#include <pthread.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#include "zdtmtst.h"

#define exit_group(code) syscall(__NR_exit_group, code)

static pthread_attr_t attr;
/* Having in mind setup with 64 Kb large pages */
static const size_t stack_size = 64 * 1024;

/*
 * Holds the chains back until all of them are created, so that
 * the setup does not compete with the churn it is setting up.
 */
static pthread_barrier_t start_barrier;

/*
 * Starting all the chains at once makes them churn in lockstep, which
 * on newer kernels makes exiting threads pile up by tens of thousands,
 * so start them one by one, this far apart.
 */
#define CHAIN_START_DELAY_US	2000
static int chains_started;

#define EAGAIN_RETRIES	50
#define EAGAIN_DELAY_US	10000

/*
 * Wrapper around pthread_create() that retries on EAGAIN.  The test
 * creates ~2048 threads in a burst and clone() can transiently fail
 * with EAGAIN due to kernel resource pressure (VMA allocator
 * contention, memory fragmentation, etc.) even when hard limits
 * are not reached.
 */
static int pthread_create_retry(pthread_t *t, const pthread_attr_t *a,
				void *(*fn)(void *), void *arg)
{
	int err, retries = 0;

	while (1) {
		err = pthread_create(t, a, fn, arg);
		if (err != EAGAIN || ++retries > EAGAIN_RETRIES)
			return err;
		usleep(EAGAIN_DELAY_US);
	}
}

static void *thread_fn(void *arg)
{
	pthread_t t, p, *self;
	int err;

	if (arg) {
		p = *(pthread_t *)arg;
		err = pthread_join(p, NULL);
		free(arg);
		if (err) {
			pr_err("pthread_join(): %d\n", err);
			return NULL;
		}
	} else {
		pthread_barrier_wait(&start_barrier);
		usleep(__atomic_fetch_add(&chains_started, 1, __ATOMIC_RELAXED) * CHAIN_START_DELAY_US);
	}

	self = malloc(sizeof(*self));
	if (!self) {
		pr_perror("malloc()");
		return NULL;
	}

	*self = pthread_self();

	err = pthread_create_retry(&t, &attr, thread_fn, self);
	if (err) {
		pr_err("pthread_create(): %d\n", err);
		free(self);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	int max_nr = 1024, i;
	char *val;
	int err;

	test_init(argc, argv);

	err = pthread_attr_init(&attr);
	if (err) {
		pr_err("pthread_attr_init(): %d\n", err);
		exit(1);
	}

	err = pthread_attr_setstacksize(&attr, stack_size);
	if (err) {
		pr_err("pthread_attr_setstacksize(): %d\n", err);
		exit(1);
	}

	val = getenv("ZDTM_THREAD_BOMB");
	if (val)
		max_nr = atoi(val);

	test_msg("%d\n", max_nr);

	err = pthread_barrier_init(&start_barrier, NULL, max_nr + 1);
	if (err) {
		pr_err("pthread_barrier_init(): %d\n", err);
		exit(1);
	}

	for (i = 0; i < max_nr; i++) {
		pthread_t p;
		err = pthread_create_retry(&p, &attr, thread_fn, NULL);
		if (err) {
			pr_err("pthread_create(): %d\n", err);
			exit(1);
		}
	}

	pthread_barrier_wait(&start_barrier);
	/* Let all the chains start. */
	usleep(max_nr * CHAIN_START_DELAY_US);

	test_daemon();
	test_waitsig();

	pass();

	return 0;
}
