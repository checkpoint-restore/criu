#include <errno.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc = "Check cpu affinity NOT restored without --cpu-affinity";
const char *test_author = "Long Wei <longwei27@huawei.com>";

int main(int argc, char **argv)
{
	cpu_set_t old;
	cpu_set_t new;

	test_init(argc, argv);

	CPU_ZERO(&old);
	CPU_ZERO(&new);

	/* Bind to CPU 0 only. */
	CPU_SET(0, &old);

	if (sched_setaffinity(getpid(), sizeof(old), &old) < 0) {
		pr_perror("Can't set cpu affinity");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	if (sched_getaffinity(getpid(), sizeof(new), &new) < 0) {
		pr_perror("Can't get cpu affinity after restore");
		exit(1);
	}

	/*
	 * Without --cpu-affinity, CRIU should NOT restore the
	 * affinity, so the process should have the default (all CPUs).
	 * We verify that the affinity is different from the one we set
	 * (which was CPU 0 only).  The .checkskip script guarantees at
	 * least 2 CPUs, so the default mask will differ from CPU 0.
	 */
	if (CPU_EQUAL(&old, &new)) {
		fail("Cpu affinity was restored without --cpu-affinity");
	} else {
		pass();
	}

	return 0;
}
