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
	FI_POST_RESTORE,
	/* not fatal */
	FI_VDSO_TRAMPOLINES = 127,
	FI_CHECK_OPEN_HANDLE = 128,
	FI_NO_MEMFD = 129,
	FI_NO_BREAKPOINTS = 130,
	FI_PARTIAL_PAGES = 131,
	FI_MAX,
};

static inline bool __fault_injected(enum faults f, enum faults fi_strategy)
{
	/*
	 * Temporary workaround for Xen guests. Breakpoints degrade
	 * performance linearly, so until we find out the reason,
	 * let's disable them.
	 */
	if (f == FI_NO_BREAKPOINTS)
		return true;

	return fi_strategy == f;
}

#ifndef CR_NOGLIBC

extern enum faults fi_strategy;
#define fault_injected(f)	__fault_injected(f, fi_strategy)

extern int fault_injection_init(void);

#else /* CR_NOGLIBC */

extern bool fault_injected(enum faults f);

#endif

#endif
