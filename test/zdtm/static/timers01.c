#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>

#include "zdtmtst.h"

const char *test_doc = "Checks non-periodic timers\n";
const char *test_author = "Andrei Vagin <avagin@gmail.com>";

static struct {
	const int timer_type;
	const int signal;
	volatile sig_atomic_t count;
} timer_tests[] = {
	/* from slowest to fastest */
	{ ITIMER_VIRTUAL, SIGVTALRM },
	{ ITIMER_PROF, SIGPROF },
	{ ITIMER_REAL, SIGALRM },
};

#define NUM_TIMERS (sizeof(timer_tests) / sizeof(timer_tests[0]))
#define TIMER_TIMEOUT 3600
#define TIMER_ALLOWED_DELTA 300

static void setup_timers(void)
{
	int i;
	struct itimerval tv = {
		.it_interval = { .tv_sec = 0, .tv_usec = 0 },
		.it_value = { .tv_sec = TIMER_TIMEOUT, .tv_usec = 0 },
	};

	for (i = 0; i < NUM_TIMERS; i++) {
		if (setitimer(timer_tests[i].timer_type, &tv, NULL) < 0) {
			pr_perror("can't set timer %d", i);
			exit(1);
		}
	}
}

static void check_timers(void)
{
	int i;

	for (i = 0; i < NUM_TIMERS; i++) {
		struct itimerval tv = {};

		if (getitimer(timer_tests[i].timer_type, &tv)) {
			pr_perror("gettimer");
			exit(1);
		}
		if (tv.it_value.tv_sec > TIMER_TIMEOUT ||
		    tv.it_value.tv_sec < TIMER_TIMEOUT - TIMER_ALLOWED_DELTA) {
			fail("%ld isn't in [%d, %d]", (long)tv.it_value.tv_sec,
					TIMER_TIMEOUT,
					TIMER_TIMEOUT - TIMER_ALLOWED_DELTA);
			exit(1);
		}
	}
	pass();
}

int main(int argc, char **argv)
{
	test_init(argc, argv);

	setup_timers();

	test_daemon();
	test_waitsig();

	check_timers();
	return 0;
}
