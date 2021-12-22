#ifndef _CRIU_LINUX_OPENAT2_H
#define _CRIU_LINUX_OPENAT2_H

#include <linux/types.h>

#include "common/config.h"

#ifdef CONFIG_HAS_OPENAT2
#include <linux/openat2.h>
#else
struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};
#endif

#endif
