#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "zdtmtst.h"

#ifndef SIGEV_THREAD_ID
#define SIGEV_THREAD_ID 4
#endif

#define TEST_INTERVAL_SEC 5
#define TEST_INTERVAL_NSEC 10000000 /* 10 ms */
#define TEST_TIMER_SEC (3600 * 5)
#define TEST_TIMER_SEC_DELTA 60
#define TEST_TIMER_NSEC 20000000

const char *test_doc = "Check that a SIGEV_THREAD_ID timer targeting a dead thread is restored as an inert timer";
const char *test_author = "Felicitas Pojtinger <felicitaspojtinger@loopholelabs.io>";

static timer_t timerid;

static void *worker(void *arg)
{
	pid_t tid;
	struct sigevent evp = {};
	struct itimerspec its = {};

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

	its.it_interval.tv_sec = TEST_INTERVAL_SEC;
	its.it_interval.tv_nsec = TEST_INTERVAL_NSEC;
	its.it_value.tv_sec = TEST_TIMER_SEC;
	its.it_value.tv_nsec = TEST_TIMER_NSEC;

	if (timer_settime(timerid, 0, &its, NULL)) {
		pr_perror("timer_settime");
		return (void *)1;
	}

	return NULL;
}

int main(int argc, char **argv)
{
	struct itimerspec its;
	pthread_t thr;
	void *ret;

	test_init(argc, argv);

	if (signal(SIGRTMIN, SIG_IGN) == SIG_ERR) {
		pr_perror("signal");
		return 1;
	}

	if (pthread_create(&thr, NULL, worker, NULL)) {
		pr_perror("pthread_create");
		return 1;
	}

	if (pthread_join(thr, &ret)) {
		pr_perror("pthread_join");
		return 1;
	}

	if (ret != NULL) {
		pr_err("Timer creation thread failed\n");
		return 1;
	}

	test_daemon();
	test_waitsig();

	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	if (timer_gettime(timerid, &its)) {
		fail("timer_gettime: timer did not survive restore");
		return 1;
	}

	if (its.it_interval.tv_sec != TEST_INTERVAL_SEC ||
	    its.it_interval.tv_nsec != TEST_INTERVAL_NSEC) {
		fail("timer_gettime: wrong interval %ld.%09ld s (expected %ld.%09ld s)",
		     (long)its.it_interval.tv_sec, (long)its.it_interval.tv_nsec,
		     (long)TEST_INTERVAL_SEC, (long)TEST_INTERVAL_NSEC);
		return 1;
	}

	if (its.it_value.tv_sec < (TEST_TIMER_SEC - TEST_TIMER_SEC_DELTA) ||
	    its.it_value.tv_sec > TEST_TIMER_SEC) {
		fail("timer_gettime: remaining time %ld.%09ld s out of expected range [%ld, %ld] s",
		     (long)its.it_value.tv_sec, (long)its.it_value.tv_nsec,
		     (long)(TEST_TIMER_SEC - TEST_TIMER_SEC_DELTA), (long)TEST_TIMER_SEC);
		return 1;
	}

	if (timer_delete(timerid)) {
		fail("timer_delete: could not delete timer post restore");
		return 1;
	}

	pass();
	return 0;
}
