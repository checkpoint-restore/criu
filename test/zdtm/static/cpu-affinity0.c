#include <errno.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "zdtmtst.h"
#include "cpu-affinity.h"

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
	cpu_set_t *mask;
	size_t size;

	mask = affinity_alloc(0, &size);
	if (!mask) {
		pr_perror("Can't allocate cpu affinity mask");
		return (void *)1;
	}

	CPU_ZERO_S(size, mask);
	CPU_SET_S(ta->cpu, size, mask);
	if (sched_setaffinity(0, size, mask) < 0) {
		pr_perror("Thread can't set cpu affinity to %d", ta->cpu);
		CPU_FREE(mask);
		return (void *)1;
	}
	CPU_FREE(mask);

	while (1)
		sleep(1);

	return NULL;
}

int main(int argc, char **argv)
{
	cpu_set_t *main_mask, *main_new, *all, *expect, *got;
	struct thread_arg args[NR_THREADS];
	int main_cpu, last, nfirst;
	int work_cpu[NR_THREADS];
	int first[NR_THREADS];
	size_t size, tsize;
	int i, cpu;

	test_init(argc, argv);

	all = affinity_alloc(0, &size);
	if (!all) {
		pr_perror("Can't get cpu affinity");
		exit(1);
	}

	nfirst = 0;
	last = -1;
	for (cpu = 0; cpu < (int)(size * 8); cpu++) {
		if (!CPU_ISSET_S(cpu, size, all))
			continue;
		if (nfirst < NR_THREADS)
			first[nfirst++] = cpu;
		last = cpu;
	}
	CPU_FREE(all);

	if (nfirst < NR_THREADS || last < 0) {
		fail("Not enough usable CPUs");
		return 0;
	}

	/*
	 * Pin the main thread to the first usable CPU, the first workers to
	 * the next ones and the last worker to the highest usable CPU.  On
	 * machines with more than 1024 CPUs the latter makes the image carry
	 * an affinity bit above 1024 and exercises the dynamic mask path.
	 */
	main_cpu = first[0];
	for (i = 0; i < NR_THREADS - 1; i++)
		work_cpu[i] = first[i + 1];
	work_cpu[NR_THREADS - 1] = last;

	for (i = 0; i < NR_THREADS; i++) {
		args[i].cpu = work_cpu[i];
		if (pthread_create(&args[i].tid, NULL, thread_fn, &args[i])) {
			pr_perror("Can't create thread %d", i);
			exit(1);
		}
	}

	main_mask = affinity_alloc(0, &size);
	if (!main_mask) {
		pr_perror("Can't allocate cpu affinity mask");
		exit(1);
	}
	CPU_ZERO_S(size, main_mask);
	CPU_SET_S(main_cpu, size, main_mask);
	if (sched_setaffinity(0, size, main_mask) < 0) {
		pr_perror("Can't set main cpu affinity");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	main_new = affinity_alloc(0, &size);
	if (!main_new) {
		pr_perror("Can't get main cpu affinity");
		exit(1);
	}
	if (!CPU_EQUAL_S(size, main_mask, main_new)) {
		fail("Main thread cpu affinity not restored");
		return 0;
	}

	for (i = 0; i < NR_THREADS; i++) {
		expect = affinity_alloc(0, &tsize);
		got = affinity_alloc(0, &tsize);
		if (!expect || !got) {
			pr_perror("Can't allocate cpu affinity mask");
			exit(1);
		}

		CPU_ZERO_S(tsize, expect);
		CPU_SET_S(work_cpu[i], tsize, expect);
		CPU_ZERO_S(tsize, got);
		if (pthread_getaffinity_np(args[i].tid, tsize, got)) {
			pr_perror("Can't get thread %d affinity", i);
			exit(1);
		}

		if (!CPU_EQUAL_S(tsize, expect, got)) {
			fail("Thread %d cpu affinity not restored (expected %d)",
			     i, work_cpu[i]);
			return 0;
		}

		CPU_FREE(expect);
		CPU_FREE(got);
	}

	CPU_FREE(main_mask);
	CPU_FREE(main_new);
	pass();
	return 0;
}
