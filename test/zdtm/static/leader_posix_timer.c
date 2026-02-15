#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "zdtmtst.h"

#ifndef SIGEV_THREAD_ID
#define SIGEV_THREAD_ID 4
#endif

const char *test_doc = "Check SIGEV_THREAD_ID timer on the thread leader";
const char *test_author = "CRIU developers";

static volatile int sigcnt;

static void timer_handler(int sig, siginfo_t *si, void *uc)
{
	sigcnt++;
}

static void *worker(void *arg)
{
	volatile int *stop = (volatile int *)arg;

	while (!*stop)
		usleep(100000);

	return NULL;
}

int main(int argc, char **argv)
{
	struct sigevent evp = {};
	struct itimerspec its = {};
	struct sigaction sa = {};
	timer_t timerid;
	pthread_t thr;
	int stop = 0;
	pid_t tid;

	test_init(argc, argv);

	/*
	 * Spawn a worker thread so the process is multithreaded.
	 * The bug only manifests when collect_threads() runs and
	 * skips vtid initialization for threads[0] (the leader).
	 */
	if (pthread_create(&thr, NULL, worker, &stop)) {
		pr_perror("pthread_create");
		return 1;
	}

	sa.sa_sigaction = timer_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGRTMIN, &sa, NULL)) {
		pr_perror("sigaction");
		return 1;
	}

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
		return 1;
	}

	its.it_interval.tv_nsec = 10000000; /* 10 ms */
	its.it_value.tv_nsec = 10000000;

	if (timer_settime(timerid, 0, &its, NULL)) {
		pr_perror("timer_settime");
		return 1;
	}

	/* Let at least one signal arrive */
	while (!sigcnt)
		usleep(1000);

	test_daemon();
	test_waitsig();

	/* Verify the timer is still running after restore */
	sigcnt = 0;
	usleep(100000); /* 100 ms – should get ~10 signals */

	if (sigcnt == 0) {
		fail("No timer signals received after restore");
		goto out;
	}

	if (timer_gettime(timerid, &its)) {
		pr_perror("timer_gettime");
		goto out;
	}

	if (its.it_interval.tv_nsec != 10000000 || its.it_interval.tv_sec) {
		fail("Wrong timer interval after restore");
		goto out;
	}

	pass();

out:
	stop = 1;
	pthread_join(thr, NULL);
	timer_delete(timerid);
	return 0;
}
