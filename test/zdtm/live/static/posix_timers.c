#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <limits.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc ="Posix timers migration check";
const char *test_author = "Kinsbursky Stanislav <skinsbursky@parallels.com>";

sigset_t mask;

#define WRONG_SIGNAL		1
#define WRONG_SI_PTR		2
#define FAIL_OVERRUN		4

#define MAX_TIMER_DISPLACEMENT	10
#define NO_PERIODIC

#ifndef NO_PERIODIC
static void realtime_periodic_handler(int sig, siginfo_t *si, void *uc);
static void monotonic_periodic_handler(int sig, siginfo_t *si, void *uc);
#endif
static void realtime_oneshot_handler(int sig, siginfo_t *si, void *uc);
static void monotonic_oneshot_handler(int sig, siginfo_t *si, void *uc);

enum {
#ifndef NO_PERIODIC
	REALTIME_PERIODIC_INFO,
	MONOTONIC_PERIODIC_INFO,
#endif
	REALTIME_ONESHOT_INFO,
	MONOTONIC_ONESHOT_INFO,
};

static struct posix_timers_info {
	char clock;
	char *name;
	void (*handler)(int sig, siginfo_t *si, void *uc);
	int sig;
	int oneshot;
	int ms_int;
	struct sigaction sa;
	int handler_status;
	int handler_cnt;
	timer_t timerid;
	int overrun;
	struct timespec start, end;
} posix_timers[] = {
#ifndef NO_PERIODIC
	[REALTIME_PERIODIC_INFO] = {CLOCK_REALTIME, "REALTIME (periodic)",
				realtime_periodic_handler, SIGALRM, 0, 1},
	[MONOTONIC_PERIODIC_INFO] = {CLOCK_MONOTONIC, "MONOTONIC (periodic)",
				monotonic_periodic_handler, SIGINT, 0, 3},
#endif
	[REALTIME_ONESHOT_INFO] = {CLOCK_REALTIME, "REALTIME (oneshot)",
				realtime_oneshot_handler, SIGUSR1, 1, INT_MAX},
	[MONOTONIC_ONESHOT_INFO] = {CLOCK_MONOTONIC, "MONOTONIC (oneshot)",
				monotonic_oneshot_handler, SIGUSR2, 1, INT_MAX},
	{ }
};

static int check_handler_status(struct posix_timers_info *info,
				struct itimerspec *its, int ms_passed, int delta)
{
	int displacement;
	int timer_ms;

	if (!info->handler_cnt && !info->oneshot) {
		fail("%s: Signal handler wasn't called\n", info->name);
		return -EINVAL;
	}

	if (info->handler_status) {
		if (info->handler_status & WRONG_SIGNAL)
			fail("%s: Handler: wrong signal received\n", info->name);
		if (info->handler_status & WRONG_SI_PTR)
			fail("%s: Handler: wrong timer address\n", info->name);
		if (info->handler_status & FAIL_OVERRUN)
			fail("%s: Handler: failed to get overrun count\n", info->name);
		return -1;
	}

	if (!info->oneshot && !its->it_value.tv_sec && !its->it_value.tv_nsec) {
		fail("%s: timer became unset\n", info->name);
		return -EFAULT;
	}

	if (info->oneshot && (its->it_interval.tv_sec || its->it_interval.tv_nsec)) {
		fail("%s: timer became periodic\n", info->name);
		return -EFAULT;
	}

	if (!info->oneshot && !its->it_interval.tv_sec && !its->it_interval.tv_nsec) {
		fail("%s: timer became oneshot\n", info->name);
		return -EFAULT;
	}

	if (info->oneshot) {
		int val = its->it_value.tv_sec * 1000 + its->it_value.tv_nsec / 1000 / 1000;
		if (info->handler_cnt) {
			if (val != 0) {
				fail("%s: timer continues ticking after expiration\n", info->name);
				return -EFAULT;
			}
			if (info->handler_cnt > 1) {
				fail("%s: timer expired %d times\n", info->name, info->handler_cnt);
				return -EFAULT;
			}
			if (info->ms_int > ms_passed) {
				fail("%s: timer expired too early\n", info->name);
				return -EFAULT;
			}
			return 0;
		}
		timer_ms = info->ms_int - val;
	} else
		timer_ms = (info->overrun + info->handler_cnt) * info->ms_int;
	displacement = (abs(ms_passed - timer_ms) - delta) * 100 / ms_passed;

	if (displacement > MAX_TIMER_DISPLACEMENT) {
		test_msg("%s: cpt/rst : %d msec\n", info->name, delta);
		test_msg("%s: Time passed (ms) : %d msec\n", info->name, ms_passed);
		test_msg("%s: Timer results    : %d msec\n", info->name, timer_ms);
		test_msg("%s: Handler count    : %d\n", info->name, info->handler_cnt);
		fail("%s: Time displacement: %d%% (max alloved: %d%%)\n", info->name, displacement, MAX_TIMER_DISPLACEMENT);
		return -EFAULT;
	}
	return 0;
}

static int check_timers(int delta)
{
	struct posix_timers_info *info = posix_timers;
	int ms_passed;
	int status = 0;
	struct itimerspec val, oldval;

	if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1) {
		fail("Failed to unlock signal\n");
		return -errno;
	}

	while (info->handler) {
		memset(&val, 0, sizeof(val));
		if (timer_settime(info->timerid, 0, &val, &oldval) == -1) {
			fail("%s: failed to reset timer\n", info->name);
			return -errno;
		}

		if (clock_gettime(info->clock, &info->end) == -1) {
			fail("Can't get %s end time\n", info->name);
			return -errno;
		}

		ms_passed = (info->end.tv_sec - info->start.tv_sec) * 1000 +
			(info->end.tv_nsec - info->start.tv_nsec) / (1000 * 1000);

		if (check_handler_status(info, &oldval, ms_passed, delta))
			status--;
		info++;
	}
	return status;
}

static void generic_handler(struct posix_timers_info *info,
			    struct posix_timers_info *real, int sig)
{
	int overrun;

	if (info != real) {
		real->handler_status |= WRONG_SI_PTR;
		return;
	}

	if (sig != info->sig)
		info->handler_status |= WRONG_SIGNAL;

	overrun = timer_getoverrun(info->timerid);
	if (overrun == -1)
		info->handler_status |= FAIL_OVERRUN;
	else
		info->overrun += overrun;
	info->handler_cnt++;
}

#ifndef NO_PERIODIC
static void monotonic_periodic_handler(int sig, siginfo_t *si, void *uc)
{
	generic_handler(si->si_value.sival_ptr,
			&posix_timers[MONOTONIC_PERIODIC_INFO], sig);
}
#endif

static void monotonic_oneshot_handler(int sig, siginfo_t *si, void *uc)
{
	generic_handler(si->si_value.sival_ptr,
			&posix_timers[MONOTONIC_ONESHOT_INFO], sig);
}

#ifndef NO_PERIODIC
static void realtime_periodic_handler(int sig, siginfo_t *si, void *uc)
{
	generic_handler(si->si_value.sival_ptr,
			&posix_timers[REALTIME_PERIODIC_INFO], sig);
}
#endif

static void realtime_oneshot_handler(int sig, siginfo_t *si, void *uc)
{
	generic_handler(si->si_value.sival_ptr,
			&posix_timers[REALTIME_ONESHOT_INFO], sig);
}

static int setup_timers(void)
{
	int i;
	int ret;
	struct posix_timers_info *info = posix_timers;
	struct sigevent sev;
	struct itimerspec its;

	sigemptyset(&mask);
	while(info->handler) {
		sigaddset(&mask, info->sig);
		info++;
	}

	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
		err("Failed to unlock signal\n");
		return -errno;
	}

	info = posix_timers;
	while(info->handler) {
		/* Add and delete fake timers to test restoring 'with holes' */
		timer_t timeridt;
		for (i = 0; i < 10; i++) {
			ret = timer_create(CLOCK_REALTIME, NULL, &timeridt);
			if (ret < 0) {
				err("Can't create temporary posix timer %lx\n", (long) timeridt);
				return -errno;
			}
			ret = timer_delete(timeridt);
			if (ret < 0) {
				err("Can't remove temporaty posix timer %lx\n", (long) timeridt);
				return -errno;
			}
		}

		info->sa.sa_flags = SA_SIGINFO;
		info->sa.sa_sigaction = info->handler;
		sigemptyset(&info->sa.sa_mask);

		if (sigaction(info->sig, &info->sa, NULL) == -1) {
			err("Failed to set SIGALRM handler\n");
			return -errno;
		}

		sev.sigev_notify = SIGEV_SIGNAL;
		sev.sigev_signo = info->sig;
		sev.sigev_value.sival_ptr = info;

		if (timer_create(info->clock, &sev, &info->timerid) == -1) {
			err("Can't create timer\n");
			return -errno;
		}

		its.it_value.tv_sec = info->ms_int / 1000;
		its.it_value.tv_nsec = info->ms_int % 1000 * 1000 * 1000;
		if (!info->oneshot) {
			its.it_interval.tv_sec = its.it_value.tv_sec;
			its.it_interval.tv_nsec = its.it_value.tv_nsec;
		} else
			its.it_interval.tv_sec = its.it_interval.tv_nsec = 0;

		if (clock_gettime(info->clock, &info->start) == -1) {
			err("Can't get %s start time\n", info->name);
			return -errno;
		}

		if (timer_settime(info->timerid, 0, &its, NULL) == -1) {
			err("Can't set timer\n");
			return -errno;
		}
		info++;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct timespec start, end;
	int err;

	test_init(argc, argv);

	err = setup_timers();
	if (err)
		return err;

	usleep(500 * 1000);

	test_daemon();

	clock_gettime(CLOCK_REALTIME, &start);
	test_waitsig();
	clock_gettime(CLOCK_REALTIME, &end);

	err = check_timers((end.tv_sec - start.tv_sec) * 1000 +
				(end.tv_nsec - start.tv_nsec) / 1000000);
	if (err)
		return err;

	pass();
	return 0;
}
