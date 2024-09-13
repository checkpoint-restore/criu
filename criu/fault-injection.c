#include <stdlib.h>
#include "criu-log.h"
#include "fault-injection.h"
#include "seize.h"

enum faults fi_strategy;

int fault_injection_init(void)
{
	char *val;
	int start;

	val = getenv("CRIU_FAULT");
	if (val == NULL)
		return 0;

	start = atoi(val);

	if (start <= 0 || start >= FI_MAX) {
		pr_err("CRIU_FAULT out of bounds.\n");
		return -1;
	}

	fi_strategy = start;

	switch (fi_strategy) {
	case FI_DISABLE_FREEZE_CGROUP:
		dont_use_freeze_cgroup();
		break;
	default:
		break;
	};
	return 0;
}
