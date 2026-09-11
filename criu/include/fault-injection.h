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
	FI_PARTIAL_PAGES = 131,
	FI_HUGE_ANON_SHMEM_ID = 132,
	FI_CANNOT_MAP_VDSO = 133,
	FI_CORRUPT_EXTREGS = 134,
	FI_DONT_USE_PAGEMAP_SCAN = 135,
	FI_DUMP_CRASH = 136,
	FI_COMPEL_INTERRUPT_ONLY_MODE = 137,
	FI_PLUGIN_CUDA_FORCE_ENABLE = 138,
	FI_NETNS_DIRECT_ROUNDTRIP_FAIL = 139,
	FI_SECCOMP_NO_IMAGE_FILTERS = 140,
	FI_SYSV_SHMEM_MAP_FILES_DENIED = 141,
	FI_MNTNS_DIRECT_MOUNT_DENIED = 142,
	FI_PIPE_RESIZE_DENIED = 143,
	FI_MNTNS_REMOUNT_DENIED = 144,
	FI_NETNS_BROKER_UNLOCK_ABSENT = 145,
	FI_NETNS_BROKER_UNLOCK_FAIL = 146,
	FI_MAX,
};

static inline bool __fault_injected(enum faults f, enum faults fi_strategy)
{
	return fi_strategy == f;
}

#define FI_HUGE_ANON_SHMEM_ID_BASE (0xfffffffflu)

#ifndef CR_NOGLIBC

extern enum faults fi_strategy;
#define fault_injected(f) __fault_injected(f, fi_strategy)

extern int fault_injection_init(void);

#else /* CR_NOGLIBC */

extern bool fault_injected(enum faults f);

#endif

#endif
