#include <stdlib.h>
#include "fault-injection.h"

enum faults fi_strategy;

int fault_injection_init()
{
	char *val;
	int strat;

	val = getenv("CRIU_FAULT");
	if (val == NULL)
		return 0;

	strat = atoi(val);

	if (strat <= 0 || strat >= FI_MAX)
		return -1;

	fi_strategy = strat;
	return 0;
}
