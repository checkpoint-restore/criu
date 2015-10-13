#ifndef __CR_FAULT_INJECTION_H__
#define __CR_FAULT_INJECTION_H__
#include <stdbool.h>

enum faults {
	FI_NONE = 0,
	FI_DUMP_EARLY,
	FI_RESTORE_ROOT_ONLY,
	FI_MAX,
};

extern enum faults fi_strategy;
extern int fault_injection_init(void);

static inline bool fault_injected(enum faults f)
{
	return fi_strategy == f;
}
#endif
