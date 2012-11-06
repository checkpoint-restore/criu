#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>

#include "zdtmtst.h"

const char *test_doc ="Posix timers migration check";
const char *test_author = "Kinsbursky Stanislav <skinsbursky@parallels.com>";

sigset_t mask;

#define WRONG_SIGNAL		1
#define WRONG_SI_PTR		2
#define FAIL_OVERRUN		4

#define MAX_TIMER_DISPLACEMENT	10

static void realtime_handler(int sig, siginfo_t *si, void *uc);
static void monotonic_handler(int sig, siginfo_t *si, void *uc);

static struct posix_timers_info {
	char clock;
	char *name;
	void (*handler)(int sig, siginfo_t *si, void *uc);
	int sig;
	int ms_int;
	struct sigaction sa;
	int handler_status;
	int handler_cnt;
	timer_t timerid;
	int overrun;
	struct timespec start, end;
} posix_timers[] = {
	[CLOCK_REALTIME] = {CLOCK_REALTIME, "REALTIME", realtime_handler, SIGALRM, 1},
	[CLOCK_MONOTONIC] = {CLOCK_MONOTONIC, "MONOTONIC", monotonic_handler, SIGINT, 3},
	{ }
};

static int check_handler_status(struct posix_timers_info *info, int ms_passed)
{
	int displacement;
	int timer_ms;

	if (!info->handler_cnt) {
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

	timer_ms = (info->overrun + info->handler_cnt) * info->ms_int;
	displacement = abs(ms_passed - timer_ms) * 100 / ms_passed;

	if (displacement > MAX_TIMER_DISPLACEMENT) {
		test_msg("%s: Time passed (ms) : %d msec\n", info->name, ms_passed);
		test_msg("%s: Timer results    : %d msec\n", info->name, timer_ms);
		test_msg("%s: Handler count    : %d\n", info->name, info->handler_cnt);
		fail("%s: Time displacement: %d%% (max alloved: %d%%)\n", info->name, displacement, MAX_TIMER_DISPLACEMENT);
		return -EFAULT;
	}
	return 0;
}

static int check_timers(void)
{
	struct posix_timers_info *info = posix_timers;
	int ms_passed;
	int status = 0;

	if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1) {
		fail("Failed to unlock signal\n");
		return -errno;
	}

	while (info->handler) {
		if (timer_delete(info->timerid) == -1) {
			fail("%s: Failed to delete timer\n", info->name);
			return -errno;
		}

		if (clock_gettime(info->clock, &info->end) == -1) {
			fail("Can't get %s end time\n", info->name);
			return -errno;
		}

		ms_passed = (info->end.tv_sec - info->start.tv_sec) * 1000 +
			(info->end.tv_nsec - info->start.tv_nsec) / (1000 * 1000);

		if (check_handler_status(info, ms_passed))
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

static void monotonic_handler(int sig, siginfo_t *si, void *uc)
{
	generic_handler(si->si_value.sival_ptr, &posix_timers[CLOCK_MONOTONIC], sig);
}

static void realtime_handler(int sig, siginfo_t *si, void *uc)
{
	generic_handler(si->si_value.sival_ptr, &posix_timers[CLOCK_REALTIME], sig);
}

static int setup_timers(void)
{
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

		its.it_value.tv_sec = 0;
		its.it_value.tv_nsec = info->ms_int * 1000 * 1000;
		its.it_interval.tv_sec = its.it_value.tv_sec;
		its.it_interval.tv_nsec = its.it_value.tv_nsec;

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
	int err;

	test_init(argc, argv);

	err = setup_timers();
	if (err)
		return err;

	usleep(500 * 1000);

	test_daemon();
	test_waitsig();

	err = check_timers();
	if (err)
		return err;

	pass();
	return 0;
}
