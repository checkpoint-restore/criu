#include <pthread.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#include "zdtmtst.h"

#define exit_group(code)	\
	syscall(__NR_exit_group, code)

static void *thread_fn(void *arg)
{
	pthread_t t, p, *self;

	if (arg) {
		p = *(pthread_t *)arg;
		pthread_join(p, NULL);
		free(arg);
	}

	self = malloc(sizeof(*self));
	*self = pthread_self();

	pthread_create(&t, NULL, thread_fn, self);
	return NULL;
}

int main(int argc, char **argv)
{
	char *val;
	int max_nr = 1024, i;

	val = getenv("ZDTM_THREAD_BOMB");
	if (val)
		max_nr = atoi(val);

	test_msg("%d\n", max_nr);

	test_init(argc, argv);

	for (i = 0; i < max_nr; i++) {
		pthread_t p;
		pthread_create(&p, NULL, thread_fn, NULL);
	}

	test_daemon();
	test_waitsig();

	pass();

	return 0;
}
