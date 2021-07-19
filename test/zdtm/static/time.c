#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "zdtmtst.h"

const char *test_doc = "Check monotonic and boot clocks";
const char *test_author = "Andrei Vagin <avagin@gmail.com";

#define NSEC_PER_SEC 1000000000ULL

int main(int argc, char **argv)
{
	struct timespec tss[2], ts;
	int clocks[] = { CLOCK_MONOTONIC, CLOCK_BOOTTIME };
	unsigned long long a, b;
	int i;

	test_init(argc, argv);

	for (i = 0; i < 2; i++)
		clock_gettime(clocks[i], &tss[i]);

	test_daemon();
	test_waitsig();

	for (i = 0; i < 2; i++) {
		clock_gettime(clocks[i], &ts);

		a = ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
		b = tss[i].tv_sec * NSEC_PER_SEC + tss[i].tv_nsec;
		if (a < b) {
			fail("%d: %lld %lld", clocks[i], a, b);
			return 1;
		}
		if (a > b + 60 * 60 * NSEC_PER_SEC) {
			fail("%d: %lld %lld", clocks[i], a, b);
			return 1;
		}
	}

	pass();

	return 0;
}
