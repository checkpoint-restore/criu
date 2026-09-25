#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/timerfd.h>

#include "zdtmtst.h"

const char *test_doc = "Check that disarmed absolute timerfds stay disarmed after restore";
const char *test_author = "Utkal Singh <singhutkal015@gmail.com>";

#define NR_TIMERS 2

static int check_disarmed(int fd, const char *name)
{
	struct itimerspec its;
	uint64_t ticks;

	if (read(fd, &ticks, sizeof(ticks)) == sizeof(ticks)) {
		fail("%s timerfd expired %llu time(s) after restore", name, (unsigned long long)ticks);
		return -1;
	}
	if (errno != EAGAIN) {
		pr_perror("Unable to read %s timerfd", name);
		return -1;
	}

	if (timerfd_gettime(fd, &its)) {
		pr_perror("Unable to get %s timerfd time", name);
		return -1;
	}
	if (its.it_value.tv_sec || its.it_value.tv_nsec) {
		fail("%s timerfd is armed after restore: it_value(%lld, %ld)", name, (long long)its.it_value.tv_sec,
		     (long)its.it_value.tv_nsec);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	const char *names[NR_TIMERS] = { "expired", "disarmed" };
	struct pollfd pfd[NR_TIMERS];
	struct itimerspec its;
	int fd[NR_TIMERS], i;
	uint64_t ticks;

	test_init(argc, argv);

	for (i = 0; i < NR_TIMERS; i++) {
		fd[i] = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
		if (fd[i] < 0) {
			pr_perror("timerfd_create failed");
			return 1;
		}
	}

	/*
	 * A one-shot absolute timer that has expired and has been read, so
	 * nothing is pending on it and it will never expire again.
	 */
	memset(&its, 0, sizeof(its));
	if (clock_gettime(CLOCK_MONOTONIC, &its.it_value)) {
		pr_perror("clock_gettime failed");
		return 1;
	}
	if (timerfd_settime(fd[0], TFD_TIMER_ABSTIME, &its, NULL)) {
		pr_perror("timerfd_settime failed");
		return 1;
	}

	pfd[0].fd = fd[0];
	pfd[0].events = POLLIN;
	if (poll(pfd, 1, -1) != 1) {
		pr_perror("Unable to wait for the timer to expire");
		return 1;
	}
	if (read(fd[0], &ticks, sizeof(ticks)) != sizeof(ticks)) {
		pr_perror("Unable to read the expired timer");
		return 1;
	}

	/* An absolute timer disarmed with a zero it_value. */
	memset(&its, 0, sizeof(its));
	if (timerfd_settime(fd[1], TFD_TIMER_ABSTIME, &its, NULL)) {
		pr_perror("timerfd_settime failed");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/*
	 * Both timers show it_value (0, 0) in fdinfo, which restore must not
	 * take for an expiration time.
	 */
	for (i = 0; i < NR_TIMERS; i++) {
		pfd[i].fd = fd[i];
		pfd[i].events = POLLIN;
	}
	if (poll(pfd, NR_TIMERS, 100) < 0) {
		pr_perror("poll failed");
		return 1;
	}

	for (i = 0; i < NR_TIMERS; i++)
		if (check_disarmed(fd[i], names[i]))
			return 1;

	pass();
	return 0;
}
