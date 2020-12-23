#include <pthread.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "zdtmtst.h"

#define exit_group(code)	\
	syscall(__NR_exit_group, code)

/* Having in mind setup with 64 Kb large pages */
static const size_t stack_size = 64 * 1024;

struct pthread_item {
	pthread_t t;
	void *stack;
	int need_join;
};

struct pthread_item *pthreads;

static void *thread_fn(void *arg)
{
	pthread_attr_t attr = {};
	long thread_id = (long)arg;
	long next_id;
	int err;

	pthreads[thread_id].need_join = 1;
	if (thread_id % 2 == 0)
		next_id = thread_id + 1;
	else
		next_id = thread_id - 1;

	if (pthreads[next_id].need_join) {
		err = pthread_join(pthreads[next_id].t, NULL);
		if (err) {
			pr_err("pthread_join(): %d\n", err);
			exit(1);
		}
	}

	err = pthread_attr_init(&attr);
	if (err) {
		pr_err("pthread_attr_init(): %d\n", err);
		exit(1);
	}

	err = pthread_attr_setstack(&attr, pthreads[next_id].stack, stack_size);
	if (err) {
		pr_err("pthread_attr_setstack(): %d\n", err);
		exit(1);
	}

	pthread_create(&pthreads[next_id].t, &attr, thread_fn, (void *)next_id);
	return NULL;
}

int main(int argc, char **argv)
{
	long max_nr = 1024, i;
	void *stack_addr;
	char *val;
	int err;

	stack_addr = mmap(NULL, stack_size * max_nr * 2,
				PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (stack_addr == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}

	pthreads = malloc(max_nr * 2 * sizeof(struct pthread_item));
	memset(pthreads, 0, max_nr * 2 * sizeof(struct pthread_item));
	for (i = 0; i < max_nr * 2; i++) {
		pthreads[i].stack = stack_addr  + i * stack_size;
	}

	val = getenv("ZDTM_THREAD_BOMB");
	if (val)
		max_nr = atoi(val);

	test_msg("%ld\n", max_nr);

	test_init(argc, argv);

	for (i = 0; i < max_nr; i++) {
		pthread_attr_t attr;

		err = pthread_attr_init(&attr);
		if (err) {
			pr_err("pthread_attr_init(): %d\n", err);
			exit(1);
		}

		err = pthread_attr_setstack(&attr, pthreads[i*2].stack, stack_size);
		if (err) {
			pr_err("pthread_attr_setstack(): %d\n", err);
			exit(1);
		}
		err = pthread_create(&pthreads[i*2].t, &attr, thread_fn, (void *)(i*2));
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
