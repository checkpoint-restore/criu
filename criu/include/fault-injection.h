#ifndef __CR_FAULT_INJECTION_H__
#define __CR_FAULT_INJECTION_H__
#include <stdbool.h>

enum faults {
	FI_NONE = 0,
	FI_DUMP_EARLY,
	FI_RESTORE_ROOT_ONLY,
	FI_DUMP_PAGES,
	FI_RESTORE_OPEN_LINK_REMAP,
	FI_PARASITE_CONNECT,
	/* not fatal */
	FI_CHECK_OPEN_HANDLE = 128,
	FI_NO_MEMFD = 129,
	FI_NO_BREAKPOINTS = 130,
	FI_MAX,
};

extern enum faults fi_strategy;
extern int fault_injection_init(void);

static inline bool fault_injected(enum faults f)
{
	return fi_strategy == f;
}
#endif
