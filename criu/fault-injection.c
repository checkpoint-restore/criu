#include <stdlib.h>
#include <string.h>
#include "criu-log.h"
#include "fault-injection.h"
#include "seize.h"

enum faults fi_strategy;

static const char *fault_names[FI_MAX] = {
	[FI_NETNS_DIRECT_ROUNDTRIP_FAIL] = "FI_NETNS_DIRECT_ROUNDTRIP_FAIL",
	[FI_NETNS_BROKER_UNLOCK_ABSENT] = "FI_NETNS_BROKER_UNLOCK_ABSENT",
	[FI_NETNS_BROKER_UNLOCK_FAIL] = "FI_NETNS_BROKER_UNLOCK_FAIL",
};

static enum faults fault_by_name(const char *name)
{
	enum faults f;

	for (f = FI_NONE + 1; f < FI_MAX; f++) {
		if (fault_names[f] && !strcmp(name, fault_names[f]))
			return f;
	}

	return FI_NONE;
}

int fault_injection_init(void)
{
	char *val;
	int start;

	val = getenv("CRIU_FAULT");
	if (val == NULL)
		return 0;

	start = fault_by_name(val);
	if (start == FI_NONE)
		start = atoi(val);

	if (start <= 0 || start >= FI_MAX) {
		pr_err("CRIU_FAULT out of bounds.\n");
		return -1;
	}

	fi_strategy = start;

	switch (fi_strategy) {
	case FI_COMPEL_INTERRUPT_ONLY_MODE:
		set_compel_interrupt_only_mode();
		break;
	default:
		break;
	};
	return 0;
}
