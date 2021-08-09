#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include <sys/eventfd.h>

#include "zdtmtst.h"

const char *test_doc = "Check SIGEV_THREAD timers";
const char *test_author = "Andrei Vagin <avagin@gmail.com>";

int efd;
static void timer_func(union sigval sigval)
{
	long long int val = 1;

	if (write(efd, &val, sizeof(val)) != sizeof(val)) {
		pr_perror("write");
		exit(1);
	}
}

#define TEST_INTERVAL_NSEC 10000000

int main(int argc, char **argv)
{
	struct sigevent evp = {};
	struct itimerspec itimerspec = {};
	long long val;
	timer_t timerid;

	test_init(argc, argv);

	efd = eventfd(0, 0);
	if (efd < 0) {
		pr_perror("eventfd");
		return 1;
	}

	evp.sigev_notify = SIGEV_THREAD;
	evp.sigev_notify_function = timer_func;
	itimerspec.it_interval.tv_nsec = TEST_INTERVAL_NSEC;
	itimerspec.it_value.tv_nsec = TEST_INTERVAL_NSEC;

	if (timer_create(CLOCK_MONOTONIC, &evp, &timerid)) {
		pr_perror("timer_create");
		exit(1);
	}

	if (timer_settime(timerid, 0, &itimerspec, NULL)) {
		pr_perror("timer_create");
		exit(1);
	}

	/* Read one event to make sure glibc allocated SIGEV_THREAD's stack */
	if (read(efd, &val, sizeof(val)) != sizeof(val)) {
		pr_perror("read");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (timer_gettime(timerid, &itimerspec)) {
		pr_perror("timer_gettime");
		exit(1);
	}

	if (itimerspec.it_interval.tv_nsec != TEST_INTERVAL_NSEC || itimerspec.it_interval.tv_sec) {
		pr_perror("wrong interval: %ld:%ld", itimerspec.it_interval.tv_sec, itimerspec.it_interval.tv_nsec);
		return 1;
	}

	/* Read old events. */
	if (read(efd, &val, sizeof(val)) != sizeof(val)) {
		pr_perror("read");
		return 1;
	}

	/* Wait for new events. */
	if (read(efd, &val, sizeof(val)) != sizeof(val)) {
		pr_perror("read");
		return 1;
	}

	pass();
	return 0;
}
