#include <sys/stat.h>

#include "criu-log.h"
#include "criu-plugin.h"

int dummy_plugin_handle_device_vma(int fd, const struct stat *stat)
{
	pr_info("dummy_plugin: Inside %s for fd = %d\n", __func__, fd);
	/* let criu report failure for the unsupported mapping */
	return -ENOTSUP;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA, dummy_plugin_handle_device_vma)

int dummy_plugin_resume_devices_late(int target_pid)
{
	pr_info("dummy_plugin: Inside %s for target pid = %d\n", __func__, target_pid);
	return -ENOTSUP;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, dummy_plugin_resume_devices_late)

/*
 * return 0 if no match found
 * return -1 for error or -ENOTSUP.
 * return 1 if vmap map must be adjusted.
 */
int dummy_plugin_update_vmamap(const char *old_path, char *new_path, const uint64_t addr, const uint64_t old_offset,
			       uint64_t *new_offset)
{
	uint64_t temp = 100;

	*new_offset = temp;
	pr_info("dummy_plugin: old_pgoff= 0x%lu new_pgoff = 0x%lx old_path = %s new_path = %s addr = 0x%lu\n",
		old_offset, *new_offset, old_path, new_path, addr);
	return -ENOTSUP;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__UPDATE_VMA_MAP, dummy_plugin_update_vmamap)
