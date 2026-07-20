#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "zdtmtst.h"

#ifndef SIGEV_THREAD_ID
#define SIGEV_THREAD_ID 4
#endif

const char *test_doc = "Check that a SIGEV_THREAD_ID timer targeting a dead thread is restored as an inert timer";
const char *test_author = "Felicitas Pojtinger <felicitaspojtinger@loopholelabs.io>";

static timer_t timerid;

static void *worker(void *arg)
{
	pid_t tid;
	struct sigevent evp = {};

	tid = syscall(SYS_gettid);

	evp.sigev_notify = SIGEV_THREAD_ID;
#ifdef __GLIBC__
	evp._sigev_un._tid = tid;
#else
	evp.sigev_notify_thread_id = tid;
#endif
	evp.sigev_signo = SIGRTMIN;

	if (timer_create(CLOCK_MONOTONIC, &evp, &timerid)) {
		pr_perror("timer_create");
		return (void *)1;
	}

	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t thr;
	void *ret;
	struct itimerspec its;

	test_init(argc, argv);

	if (pthread_create(&thr, NULL, worker, NULL)) {
		pr_perror("pthread_create");
		return 1;
	}

	if (pthread_join(thr, &ret)) {
		pr_perror("pthread_join");
		return 1;
	}

	if (ret != NULL) {
		fail("Timer creation thread failed");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/*
	 * The notify thread exited before checkpoint, so the timer is
	 * restored as an inert SIGEV_NONE timer rather than being dropped.
	 * It must still exist afterwards, which we verify by querying it.
	 */
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 0;
	if (timer_gettime(timerid, &its)) {
		fail("timer_gettime: timer did not survive restore");
		return 1;
	}

	if (timer_delete(timerid)) {
		fail("timer_gettime: could not delete timer post restore");
		return 1;
	}

	pass();
	return 0;
}
