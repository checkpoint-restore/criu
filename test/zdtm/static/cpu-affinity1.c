#include <errno.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>

#include "zdtmtst.h"
#include "cpu-affinity.h"

const char *test_doc = "Check cpu affinity NOT restored without --cpu-affinity";
const char *test_author = "Long Wei <longwei27@huawei.com>";

int main(int argc, char **argv)
{
	cpu_set_t *old, *new;
	size_t size;
	int cpu;

	test_init(argc, argv);

	old = affinity_alloc(0, &size);
	if (!old) {
		pr_perror("Can't allocate cpu affinity mask");
		exit(1);
	}

	cpu = affinity_first_cpu(size, old);
	if (cpu < 0) {
		fail("No usable CPU found");
		return 0;
	}

	/* Bind to a single usable CPU. */
	CPU_ZERO_S(size, old);
	CPU_SET_S(cpu, size, old);
	if (sched_setaffinity(0, size, old) < 0) {
		pr_perror("Can't set cpu affinity");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	new = affinity_alloc(0, &size);
	if (!new) {
		pr_perror("Can't get cpu affinity after restore");
		exit(1);
	}

	/*
	 * Without --cpu-affinity, CRIU should NOT restore the affinity, so
	 * the process should have the default (all usable) CPUs.  The
	 * .checkskip script guarantees at least 2 usable CPUs, so the
	 * default mask differs from the single CPU pinned above.
	 */
	if (CPU_EQUAL_S(size, old, new)) {
		fail("Cpu affinity was restored without --cpu-affinity");
	} else {
		pass();
	}

	CPU_FREE(old);
	CPU_FREE(new);
	return 0;
}
