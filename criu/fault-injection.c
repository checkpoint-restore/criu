#include <stdlib.h>
#include "fault-injection.h"

enum faults fi_strategy;

int fault_injection_init()
{
	char *val;
	int start;

	val = getenv("CRIU_FAULT");
	if (val == NULL)
		return 0;

	start = atoi(val);

	if (start <= 0 || start >= FI_MAX)
		return -1;

	fi_strategy = start;
	return 0;
}
