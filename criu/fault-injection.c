#include <stdlib.h>
#include <string.h>
#include "criu-log.h"
#include "fault-injection.h"
#include "seize.h"

enum faults fi_strategy;

static const char *fault_names[FI_MAX] = {
	[FI_DUMP_EARLY] = "FI_DUMP_EARLY",
	[FI_RESTORE_ROOT_ONLY] = "FI_RESTORE_ROOT_ONLY",
	[FI_DUMP_PAGES] = "FI_DUMP_PAGES",
	[FI_RESTORE_OPEN_LINK_REMAP] = "FI_RESTORE_OPEN_LINK_REMAP",
	[FI_PARASITE_CONNECT] = "FI_PARASITE_CONNECT",
	[FI_POST_RESTORE] = "FI_POST_RESTORE",
	[FI_VDSO_TRAMPOLINES] = "FI_VDSO_TRAMPOLINES",
	[FI_CHECK_OPEN_HANDLE] = "FI_CHECK_OPEN_HANDLE",
	[FI_NO_MEMFD] = "FI_NO_MEMFD",
	[FI_PARTIAL_PAGES] = "FI_PARTIAL_PAGES",
	[FI_HUGE_ANON_SHMEM_ID] = "FI_HUGE_ANON_SHMEM_ID",
	[FI_CANNOT_MAP_VDSO] = "FI_CANNOT_MAP_VDSO",
	[FI_CORRUPT_EXTREGS] = "FI_CORRUPT_EXTREGS",
	[FI_DONT_USE_PAGEMAP_SCAN] = "FI_DONT_USE_PAGEMAP_SCAN",
	[FI_DUMP_CRASH] = "FI_DUMP_CRASH",
	[FI_COMPEL_INTERRUPT_ONLY_MODE] = "FI_COMPEL_INTERRUPT_ONLY_MODE",
	[FI_PLUGIN_CUDA_FORCE_ENABLE] = "FI_PLUGIN_CUDA_FORCE_ENABLE",
	[FI_NETNS_DIRECT_ROUNDTRIP_FAIL] = "FI_NETNS_DIRECT_ROUNDTRIP_FAIL",
	[FI_SECCOMP_NO_IMAGE_FILTERS] = "FI_SECCOMP_NO_IMAGE_FILTERS",
	[FI_SYSV_SHMEM_MAP_FILES_DENIED] = "FI_SYSV_SHMEM_MAP_FILES_DENIED",
	[FI_MNTNS_DIRECT_MOUNT_DENIED] = "FI_MNTNS_DIRECT_MOUNT_DENIED",
	[FI_PIPE_RESIZE_DENIED] = "FI_PIPE_RESIZE_DENIED",
	[FI_MNTNS_REMOUNT_DENIED] = "FI_MNTNS_REMOUNT_DENIED",
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
