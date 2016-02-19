#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "zdtmtst.h"

const char *test_doc	= "Check (via pthread/NPTL) that futeces behave through migration";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

volatile int kid_passed;

void *thread_fn(void *lock)
{
	pthread_mutex_t *mutex;

	mutex = (pthread_mutex_t *)lock;
	pthread_mutex_lock(mutex);
	kid_passed++;
	pthread_mutex_unlock(mutex);
	return NULL;
}

#define DEF_NUM_THREADS	10
#define MAX_NUM_THREADS	50
int num_threads = DEF_NUM_THREADS;
TEST_OPTION(num_threads, int, "number of threads "
		"(default " __stringify(DEF_NUM_THREADS)
		" maximum " __stringify(MAX_NUM_THREADS) ")", 0);

int main(int argc, char **argv)
{
	int i;
	pthread_t thr[num_threads];
	pthread_mutex_t m;

	test_init(argc, argv);

	if (num_threads > MAX_NUM_THREADS) {
		pr_perror("%d threads it too much. max is %d",
				num_threads, MAX_NUM_THREADS);
		goto out;
	}

	pthread_mutex_init(&m, NULL);
	pthread_mutex_lock(&m);

	for (i = 0; i < num_threads; i++)
		if (pthread_create(&thr[i], NULL, thread_fn, &m)) {
			pr_perror("Can't create %d'th thread", i + 1);
			goto out_kill;
		}

	kid_passed = 0;

	test_daemon();
	test_waitsig();

	sleep(1);
	if (kid_passed != 0)
		fail("some kids broke through\n");

	pthread_mutex_unlock(&m);
	for (i = 0; i < num_threads; i++)
		pthread_join(thr[i], NULL);

	if (pthread_mutex_trylock(&m)) {
		if (errno == EBUSY)
			fail("kids left my mutex locked\n");
		else
			pr_perror("kids spoiled my mutex");
	}

	if (kid_passed != num_threads)
		fail("some kids died during migration\n");

	pass();
out:
	return 0;

out_kill:
	for (i--; i >= 0; i--) {
		pthread_kill(thr[i], SIGKILL);
		pthread_join(thr[i], NULL);
	}
	goto out;
}
