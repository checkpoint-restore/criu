#include <errno.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc = "Check cpu affinity fallback on cross-topology restore";
const char *test_author = "Long Wei <longwei27@huawei.com>";

int main(int argc, char **argv)
{
	cpu_set_t old;
	cpu_set_t new;

	test_init(argc, argv);

	/* Bind to CPU 0 only. */
	CPU_ZERO(&old);
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
	 * The --pre-restore hook rewrites the image's cpu affinity mask
	 * to reference a CPU that does not exist on the restore host.
	 * cpu_affinity_compatible() detects that the image mask is not
	 * a subset of the restore host's available CPUs and falls back
	 * to skipping affinity restore. The restored process therefore
	 * inherits the default affinity (all online CPUs), which differs
	 * from the originally pinned CPU 0.
	 */
	if (CPU_EQUAL(&old, &new)) {
		fail("Cpu affinity was restored despite topology mismatch");
	} else {
		pass();
	}

	return 0;
}
