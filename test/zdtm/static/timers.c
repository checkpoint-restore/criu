#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>

#include "zdtmtst.h"

const char *test_doc = "Checks timers keep ticking after migration\n";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

static struct {
	const int timer_type;
	const int signal;
	volatile sig_atomic_t count;
} timer_tests[] = {	/* from slowest to fastest */
	{ ITIMER_VIRTUAL,	SIGVTALRM	},
	{ ITIMER_PROF,		SIGPROF		},
	{ ITIMER_REAL,		SIGALRM		},
};

#define NUM_TIMERS	(sizeof(timer_tests) / sizeof(timer_tests[0]))
#define MAX_TIMER_COUNT	10

static void timer_tick(int sig)
{
	int i;
	for (i = 0; i < NUM_TIMERS; i++)
		if (timer_tests[i].signal == sig) {
			/* don't go beyond MAX_TIMER_COUNT, to avoid overflow */
			if (timer_tests[i].count < MAX_TIMER_COUNT)
				timer_tests[i].count++;
			break;
		}
}

static void setup_timers(void)
{
	int i;
	struct itimerval tv = {
		.it_interval = {
			.tv_sec = 0,
			.tv_usec = 100000
		},
		.it_value = {
			.tv_sec = 0,
			.tv_usec = 100
		},
	};

	for (i = 0; i < NUM_TIMERS; i++) {
		if (signal(timer_tests[i].signal, timer_tick) == SIG_ERR) {
			pr_perror("can't set signal handler %d", i);
			exit(1);
		}

		if (setitimer(timer_tests[i].timer_type, &tv, NULL) < 0) {
			pr_perror("can't set timer %d", i);
			exit(1);
		}
	}
}

static void check_timers(void)
{
	int i;
	volatile unsigned int j;	/* avoid optimizing the loop away */

	for (i = 0; i < NUM_TIMERS; i++)	/* reset counters first */
		timer_tests[i].count = 0;

	/* waste some real and CPU time: run for MAX_TIMER_COUNT ticks or until
	 * j overflows */
	for (j = 1; j && timer_tests[0].count < MAX_TIMER_COUNT; j++);

	for (i = 0; i < NUM_TIMERS; i++)
		if (!timer_tests[i].count) {
			fail("timer %d stuck", i);
			return;
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
