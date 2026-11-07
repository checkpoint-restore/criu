#include <errno.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>

#include "zdtmtst.h"
#include "cpu-affinity.h"

const char *test_doc = "Check cpu affinity fallback on cross-topology restore";
const char *test_author = "Long Wei <longwei27@huawei.com>";

int main(int argc, char **argv)
{
	cpu_set_t *full, *old, *new;
	size_t size;
	int cpu;

	test_init(argc, argv);

	/* Remember the default (usable) affinity before pinning. */
	full = affinity_alloc(0, &size);
	if (!full) {
		pr_perror("Can't get default cpu affinity");
		exit(1);
	}

	cpu = affinity_first_cpu(size, full);
	if (cpu < 0) {
		fail("No usable CPU found");
		return 0;
	}

	old = affinity_alloc(0, &size);
	if (!old) {
		pr_perror("Can't allocate cpu affinity mask");
		exit(1);
	}
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
	 * The --pre-restore hook rewrites the image's cpu affinity mask to
	 * reference a CPU that is not available on the restore host.
	 * cpu_affinity_compatible() detects that mismatch and falls back to
	 * skipping the restore, so the restored process keeps the default
	 * affinity instead of the single CPU pinned above.
	 *
	 * When the process may use only one CPU, a skipped restore and a
	 * successful restore of that CPU are indistinguishable, so only flag
	 * the mismatch when there was more than one CPU to fall back to.
	 */
	if (CPU_EQUAL_S(size, old, new) && CPU_COUNT_S(size, full) > 1) {
		fail("Cpu affinity was restored despite topology mismatch");
	} else {
		pass();
	}

	CPU_FREE(full);
	CPU_FREE(old);
	CPU_FREE(new);
	return 0;
}
