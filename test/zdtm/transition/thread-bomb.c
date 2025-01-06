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
	}

	self = malloc(sizeof(*self));
	if (!self) {
		pr_perror("malloc()");
		return NULL;
	}

	*self = pthread_self();

	err = pthread_create(&t, &attr, thread_fn, self);
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

	for (i = 0; i < max_nr; i++) {
		pthread_t p;
		err = pthread_create(&p, &attr, thread_fn, NULL);
		if (err) {
			pr_err("pthread_create(): %d\n", err);
			exit(1);
		}
	}

	test_daemon();
	test_waitsig();

	pass();

	return 0;
}
