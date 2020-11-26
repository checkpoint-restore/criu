#include <errno.h>
#include <stdlib.h>
#include <sched.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that with-cpu-affinity option can restore cpu affinity";
const char *test_author	= "Sang Yan <sangyan@huawei.com>";

int main(int argc, char **argv)
{
	cpu_set_t old;
	cpu_set_t new;

	test_init(argc, argv);

	CPU_ZERO(&old);
	CPU_ZERO(&new);

	/* test only 0 core because of CI test env limited */
	CPU_SET(0, &old);

	if (sched_setaffinity(getpid(), sizeof(old), &old) < 0) {
		pr_perror("Can't set old cpu affinity! errno: %d", errno);
		exit(1);
	}

	test_daemon();
	test_waitsig();

	if (sched_getaffinity(getpid(), sizeof(new), &new) < 0) {
		pr_perror("Can't get new cpu affinity! errno: %d", errno);
		exit(1);
	}

	if (memcmp(&old, &new, sizeof(cpu_set_t)))
		fail("Cpu affinity restore failed.");
	else
		pass();

	return 0;
}
