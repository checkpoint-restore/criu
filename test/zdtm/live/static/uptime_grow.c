#include "zdtmtst.h"

const char *test_doc    = "test to ensure that monotonic clock doesn't decrease";
const char *test_author = "Evgeny Antysev <eantyshev@parallels.com>";

#include <time.h>
#include <stdlib.h>

# define tv_ge(a, b) \
  (((a)->tv_sec == (b)->tv_sec) ? \
   ((a)->tv_nsec >= (b)->tv_nsec) : \
   ((a)->tv_sec > (b)->tv_sec))

int main(int argc, char **argv)
{
	struct timespec tm_old, tm, ts;
	double diff_nsec;
	ts.tv_sec = 0;
	ts.tv_nsec = 1000000;

	test_init(argc, argv);

	if (clock_gettime(CLOCK_MONOTONIC, &tm_old)) {
		err("clock_gettime failed: %m\n");
		exit(1);
	}

	test_daemon();

	while (test_go()) {
		if (clock_gettime(CLOCK_MONOTONIC, &tm)) {
			err("clock_gettime failed: %m\n");
			exit(1);
		}
		if (!tv_ge(&tm, &tm_old)) {
			diff_nsec = (tm_old.tv_sec - tm.tv_sec) * 1.0E9 +\
				(tm_old.tv_nsec - tm.tv_nsec);
			fail("clock step backward for %e nsec\n", diff_nsec);
			exit(1);
		}
		tm_old = tm;
		/*
		Kernel can't suspend container by design if calls
		clock_gettime() in a loop, so we need to sleep
		between clock_gettime().
		*/
		nanosleep(&ts, NULL);
	}
	pass();
	return 0;
}
