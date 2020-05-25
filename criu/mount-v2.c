#include "kerndat.h"
#include "log.h"

#undef LOG_PREFIX
#define LOG_PREFIX "mnt-v2: "

int check_mount_v2(void)
{
	if (!kdat.has_move_mount_set_group) {
		pr_warn("Mounts-v2 requires MOVE_MOUNT_SET_GROUP support\n");
		return -1;
	}

	if (!kdat.has_openat2) {
		pr_warn("Mounts-v2 requires openat2 support\n");
		return -1;
	}

	return 0;
}
