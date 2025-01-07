#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <limits.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc = "Posix timers migration check";
const char *test_author = "Kinsbursky Stanislav <skinsbursky@parallels.com>";

sigset_t mask;

#define WRONG_SIGNAL 1
#define WRONG_SI_PTR 2
#define FAIL_OVERRUN 4

#define MAX_TIMER_DISPLACEMENT 10
#define NO_PERIODIC

#ifndef CLOCK_MONOTONIC_COARSE
#define CLOCK_MONOTONIC_COARSE 6
#endif

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

#ifndef NO_PERIODIC
static void realtime_periodic_handler(int sig, siginfo_t *si, void *uc);
static void monotonic_periodic_handler(int sig, siginfo_t *si, void *uc);
static void boottime_periodic_handler(int sig, siginfo_t *si, void *uc);
#endif
static void realtime_oneshot_handler(int sig, siginfo_t *si, void *uc);
static void monotonic_oneshot_handler(int sig, siginfo_t *si, void *uc);
static void boottime_oneshot_handler(int sig, siginfo_t *si, void *uc);

enum {
#ifndef NO_PERIODIC
	REALTIME_PERIODIC_INFO,
	MONOTONIC_PERIODIC_INFO,
	BOOTTIME_PERIODIC_INFO,
#endif
	REALTIME_ONESHOT_INFO,
	MONOTONIC_ONESHOT_INFO,
	BOOTTIME_ONESHOT_INFO,
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
	[REALTIME_PERIODIC_INFO] = {
		.clock		= CLOCK_REALTIME,
		.name		= "REALTIME (periodic)",
		.handler	= realtime_periodic_handler,
		.sig		= SIGALRM,
		.oneshot	= 0,
		.ms_int		= 1,
	},
	[MONOTONIC_PERIODIC_INFO] = {
		.clock		= CLOCK_MONOTONIC,
		.name		= "MONOTONIC (periodic)",
		.handler	= monotonic_periodic_handler,
		.sig		= SIGINT,
		.oneshot	= 0,
		.ms_int		= 3,
	},
	[BOOTTIME_PERIODIC_INFO] = {
		.clock		= CLOCK_BOOTTIME,
		.name		= "BOOTTIME (periodic)",
		.handler	= boottime_periodic_handler,
		.sig		= SIGWINCH,
		.oneshot	= 0,
		.ms_int		= 3,
	},
#endif
	[REALTIME_ONESHOT_INFO] = {
		.clock		= CLOCK_REALTIME,
		.name		= "REALTIME (oneshot)",
		.handler	= realtime_oneshot_handler,
		.sig		= SIGUSR1,
		.oneshot	= 1,
		.ms_int		= INT_MAX,
	},
	[MONOTONIC_ONESHOT_INFO] = {
		.clock		= CLOCK_MONOTONIC,
		.name		= "MONOTONIC (oneshot)",
		.handler	= monotonic_oneshot_handler,
		.sig		= SIGUSR2,
		.oneshot	= 1,
		.ms_int		= INT_MAX,
	},
	[BOOTTIME_ONESHOT_INFO] = {
		.clock		= CLOCK_BOOTTIME,
		.name		= "BOOTTIME (oneshot)",
		.handler	= boottime_oneshot_handler,
		.sig		= SIGPROF,
		.oneshot	= 1,
		.ms_int		= INT_MAX,
	},
	{ }
};

static int check_handler_status(struct posix_timers_info *info, struct itimerspec *its, int ms_passed, int delta)
{
	int displacement;
	int timer_ms;

	if (!info->handler_cnt && !info->oneshot) {
		fail("%s: Signal handler wasn't called", info->name);
		return -EINVAL;
	}

	if (info->handler_status) {
		if (info->handler_status & WRONG_SIGNAL)
			fail("%s: Handler: wrong signal received", info->name);
		if (info->handler_status & WRONG_SI_PTR)
			fail("%s: Handler: wrong timer address", info->name);
		if (info->handler_status & FAIL_OVERRUN)
			fail("%s: Handler: failed to get overrun count", info->name);
		return -1;
	}

	if (!info->oneshot && !its->it_value.tv_sec && !its->it_value.tv_nsec) {
		fail("%s: timer became unset", info->name);
		return -EFAULT;
	}

	if (info->oneshot && (its->it_interval.tv_sec || its->it_interval.tv_nsec)) {
		fail("%s: timer became periodic", info->name);
		return -EFAULT;
	}

	if (!info->oneshot && !its->it_interval.tv_sec && !its->it_interval.tv_nsec) {
		fail("%s: timer became oneshot", info->name);
		return -EFAULT;
	}

	if (info->oneshot) {
		int val = its->it_value.tv_sec * 1000 + its->it_value.tv_nsec / 1000 / 1000;
		if (info->handler_cnt) {
			if (val != 0) {
				fail("%s: timer continues ticking after expiration", info->name);
				return -EFAULT;
			}
			if (info->handler_cnt > 1) {
				fail("%s: timer expired %d times", info->name, info->handler_cnt);
				return -EFAULT;
			}
			if (info->ms_int > ms_passed) {
				fail("%s: timer expired too early", info->name);
				return -EFAULT;
			}
			return 0;
		}
		timer_ms = info->ms_int - val;
	} else
		timer_ms = (info->overrun + info->handler_cnt) * info->ms_int;
	displacement = (abs(ms_passed - timer_ms) - delta) * 100 / ms_passed;

	test_msg("%20s: cpt/rst          : %-8d msec\n", info->name, delta);
	test_msg("%20s: Time passed (ms) : %-8d msec\n", info->name, ms_passed);
	test_msg("%20s: Timer results    : %-8d msec\n", info->name, timer_ms);
	test_msg("%20s: Handler count    : %d\n", info->name, info->handler_cnt);

	if (displacement > MAX_TIMER_DISPLACEMENT) {
		fail("%32s: Time displacement: %d%% (max alloved: %d%%)", info->name, displacement,
		     MAX_TIMER_DISPLACEMENT);
		return -EFAULT;
	}
	return 0;
}

static int check_timers(int delta, struct timespec *sleep_start, struct timespec *sleep_end)
{
	struct posix_timers_info *info = posix_timers;
	int ms_passed;
	int status = 0;
	struct itimerspec val, oldval;

	if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1) {
		fail("Failed to unlock signal");
		return -errno;
	}

	while (info->handler) {
		memset(&val, 0, sizeof(val));
		if (timer_settime(info->timerid, 0, &val, &oldval) == -1) {
			fail("%s: failed to reset timer", info->name);
			return -errno;
		}

		if (clock_gettime(info->clock, &info->end) == -1) {
			fail("Can't get %s end time", info->name);
			return -errno;
		}

		/*
		 * Adjust with @total_sleep_time if needed.
		 */
		if (info->clock == CLOCK_BOOTTIME) {
			info->start.tv_sec -= sleep_start->tv_sec;
			info->start.tv_nsec -= sleep_start->tv_nsec;
			info->end.tv_sec -= sleep_end->tv_sec;
			info->end.tv_nsec -= sleep_end->tv_nsec;
		}

		ms_passed = (info->end.tv_sec - info->start.tv_sec) * 1000 +
			    (info->end.tv_nsec - info->start.tv_nsec) / (1000 * 1000);

		if (check_handler_status(info, &oldval, ms_passed, delta))
			status--;
		info++;
	}
	return status;
}

static void generic_handler(struct posix_timers_info *info, struct posix_timers_info *real, int sig)
{
	int overrun;

	if (info == NULL)
		info = &posix_timers[MONOTONIC_ONESHOT_INFO];

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
	generic_handler(si->si_value.sival_ptr, &posix_timers[MONOTONIC_PERIODIC_INFO], sig);
}

static void boottime_periodic_handler(int sig, siginfo_t *si, void *uc)
{
	generic_handler(si->si_value.sival_ptr, &posix_timers[BOOTTIME_PERIODIC_INFO], sig);
}
#endif

static void monotonic_oneshot_handler(int sig, siginfo_t *si, void *uc)
{
	generic_handler(si->si_value.sival_ptr, &posix_timers[MONOTONIC_ONESHOT_INFO], sig);
}

static void boottime_oneshot_handler(int sig, siginfo_t *si, void *uc)
{
	generic_handler(si->si_value.sival_ptr, &posix_timers[BOOTTIME_ONESHOT_INFO], sig);
}

#ifndef NO_PERIODIC
static void realtime_periodic_handler(int sig, siginfo_t *si, void *uc)
{
	generic_handler(si->si_value.sival_ptr, &posix_timers[REALTIME_PERIODIC_INFO], sig);
}
#endif

static void realtime_oneshot_handler(int sig, siginfo_t *si, void *uc)
{
	generic_handler(si->si_value.sival_ptr, &posix_timers[REALTIME_ONESHOT_INFO], sig);
}

static int setup_timers(void)
{
	int i;
	int ret;
	struct posix_timers_info *info = posix_timers;
	struct sigevent sev;
	struct itimerspec its;

	sigemptyset(&mask);
	while (info->handler) {
		sigaddset(&mask, info->sig);
		info++;
	}

	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
		pr_perror("Failed to unlock signal");
		return -errno;
	}

	info = posix_timers;
	while (info->handler) {
		/* Add and delete fake timers to test restoring 'with holes' */
		timer_t timeridt;
		for (i = 0; i < 10; i++) {
			ret = timer_create(CLOCK_REALTIME, NULL, &timeridt);
			if (ret < 0) {
				pr_perror("Can't create temporary posix timer %lx", (long)timeridt);
				return -errno;
			}
			ret = timer_delete(timeridt);
			if (ret < 0) {
				pr_perror("Can't remove temporaty posix timer %lx", (long)timeridt);
				return -errno;
			}
		}

		info->sa.sa_flags = SA_SIGINFO;
		info->sa.sa_sigaction = info->handler;
		sigemptyset(&info->sa.sa_mask);

		if (sigaction(info->sig, &info->sa, NULL) == -1) {
			pr_perror("Failed to set SIGALRM handler");
			return -errno;
		}

		sev.sigev_notify = SIGEV_SIGNAL;
		sev.sigev_signo = info->sig;
		if (&posix_timers[MONOTONIC_ONESHOT_INFO] == info)
			sev.sigev_value.sival_ptr = NULL;
		else
			sev.sigev_value.sival_ptr = info;

		if (timer_create(info->clock, &sev, &info->timerid) == -1) {
			pr_perror("Can't create timer");
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
			pr_perror("Can't get %s start time", info->name);
			return -errno;
		}

		if (timer_settime(info->timerid, 0, &its, NULL) == -1) {
			pr_perror("Can't set timer");
			return -errno;
		}
		info++;
	}
	return 0;
}

/*
 * Figure out @total_sleep_time, ie time the system was in hardware
 * suspend mode, will need this value to exclude from boottime clock
 * testing.
 */
static int get_total_sleep_time(struct timespec *tv, char *type)
{
	struct timespec boottime_coarse;
	struct timespec boottime;

	if (clock_gettime(CLOCK_BOOTTIME, &boottime) == -1) {
		pr_perror("Can't get CLOCK_BOOTTIME %s time", type);
		return -errno;
	}

	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &boottime_coarse) == -1) {
		pr_perror("Can't get CLOCK_MONOTONIC_COARSE %s time", type);
		return -errno;
	}

	tv->tv_sec = boottime.tv_sec - boottime_coarse.tv_sec;
	tv->tv_nsec = boottime.tv_nsec - boottime_coarse.tv_nsec;

	test_msg("(%6s) boottime %lu "
		 "boottime-coarse %lu "
		 "total_sleep_time %lu\n",
		 type, (long)boottime.tv_sec, (long)boottime_coarse.tv_sec, (long)tv->tv_sec);

	return 0;
}

int main(int argc, char **argv)
{
	struct timespec sleep_start, sleep_end;
	struct timespec start, end;
	int err;

	test_init(argc, argv);

	err = setup_timers();
	if (err)
		return err;

	usleep(500 * 1000);

	clock_gettime(CLOCK_REALTIME, &start);
	err = get_total_sleep_time(&sleep_start, "start");
	if (err)
		return err;

	test_daemon();
	test_waitsig();

	clock_gettime(CLOCK_REALTIME, &end);
	err = get_total_sleep_time(&sleep_end, "end");
	if (err)
		return err;
	err = check_timers((end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000, &sleep_start,
			   &sleep_end);
	if (err)
		return err;

	pass();
	return 0;
}
