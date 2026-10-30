#include <errno.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check --cpu-affinity restores per-thread affinity";
const char *test_author = "Long Wei <longwei27@huawei.com>";

#define NR_THREADS 4

struct thread_arg {
	int cpu;
	pthread_t tid;
};

static void *thread_fn(void *arg)
{
	struct thread_arg *ta = arg;
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(ta->cpu, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask) < 0) {
		pr_perror("Thread can't set cpu affinity to %d", ta->cpu);
		return (void *)1;
	}

	while (1)
		sleep(1);

	return NULL;
}

int main(int argc, char **argv)
{
	struct thread_arg args[NR_THREADS];
	cpu_set_t main_mask, main_new;
	int i;

	test_init(argc, argv);

	/* Spawn NR_THREADS worker threads, each pinned to a distinct CPU. */
	for (i = 0; i < NR_THREADS; i++) {
		args[i].cpu = i + 1;
		if (pthread_create(&args[i].tid, NULL, thread_fn, &args[i])) {
			pr_perror("Can't create thread %d", i);
			exit(1);
		}
	}

	/* Main thread pinned to CPU 0. */
	CPU_ZERO(&main_mask);
	CPU_SET(0, &main_mask);
	if (sched_setaffinity(0, sizeof(main_mask), &main_mask) < 0) {
		pr_perror("Can't set main cpu affinity");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	/* Verify main thread affinity. */
	if (sched_getaffinity(0, sizeof(main_new), &main_new) < 0) {
		pr_perror("Can't get main cpu affinity");
		exit(1);
	}

	if (!CPU_EQUAL(&main_mask, &main_new)) {
		fail("Main thread cpu affinity not restored");
		return 0;
	}

	/* Verify each worker thread kept its own CPU. */
	for (i = 0; i < NR_THREADS; i++) {
		cpu_set_t expect, got;

		CPU_ZERO(&expect);
		CPU_SET(i + 1, &expect);

		if (pthread_getaffinity_np(args[i].tid, sizeof(got), &got)) {
			pr_perror("Can't get thread %d affinity", i);
			exit(1);
		}

		if (!CPU_EQUAL(&expect, &got)) {
			fail("Thread %d cpu affinity not restored (expected %d)",
			     i, i + 1);
			return 0;
		}
	}

	pass();
	return 0;
}
