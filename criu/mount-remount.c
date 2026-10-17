#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/mount.h>

#include "log.h"
#include "mount.h"

#ifndef MS_STRICTATIME
#define MS_STRICTATIME (1 << 24)
#endif
#define MS_MNT_ATIME_FLAGS (MS_NOATIME | MS_NODIRATIME | MS_RELATIME | MS_STRICTATIME)

int remount_root_flags(const char *target, unsigned long mflags)
{
	if (mount(NULL, target, NULL, MS_REMOUNT | MS_BIND | mflags, NULL) == 0)
		return 0;

	/* If dumped flags carry no atime bits, kernel lock cannot be atime-related; do not retry */
	if (errno == EPERM && (mflags & MS_MNT_ATIME_FLAGS)) {
		unsigned long fallback = mflags & ~MS_MNT_ATIME_FLAGS;

		/* If only atime flags were specified, no secondary mount() syscall is needed */
		if (!fallback || mount(NULL, target, NULL, MS_REMOUNT | MS_BIND | fallback, NULL) == 0) {
			pr_warn("mnt: root atime flags locked by kernel, keeping current options\n");
			return 0;
		}
	}

	pr_perror("Unable to apply root mount options");
	return -1;
}
