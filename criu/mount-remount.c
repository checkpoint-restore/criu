#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/mount.h>

#include "log.h"
#include "mount.h"

int remount_root_flags(const char *target, unsigned long mflags, bool *atime_dropped)
{
	if (atime_dropped)
		*atime_dropped = false;

	if (mount(NULL, target, NULL, MS_REMOUNT | MS_BIND | mflags, NULL) == 0)
		return 0;

	/* If dumped flags carry no atime bits, kernel lock cannot be atime-related; do not retry */
	if (errno == EPERM && (mflags & MS_MNT_ATIME_FLAGS)) {
		unsigned long fallback = mflags & ~MS_MNT_ATIME_FLAGS;

		/* Always retry: missing ro/nosuid/nodev/noexec bits ask the kernel to clear them */
		if (mount(NULL, target, NULL, MS_REMOUNT | MS_BIND | fallback, NULL) == 0) {
			if (atime_dropped)
				*atime_dropped = true;
			pr_warn("mnt: root atime flags locked by kernel, keeping current options\n");
			return 0;
		}
	}

	pr_perror("Unable to apply root mount options");
	return -1;
}
