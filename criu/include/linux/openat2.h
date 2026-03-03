#ifndef _CRIU_LINUX_OPENAT2_H
#define _CRIU_LINUX_OPENAT2_H

#include <linux/types.h>

#ifdef __has_include
#if __has_include("common/config.h")
#include "common/config.h"
#endif
#endif

/*
 * If CONFIG_HAS_OPENAT2 is set (from config.h) or the system header
 * has already been included (e.g. via glibc's fcntl.h), use the real
 * definitions.  Otherwise provide a fallback.
 */
#if defined(CONFIG_HAS_OPENAT2) || defined(_LINUX_OPENAT2_H)
#ifndef _LINUX_OPENAT2_H
#include <linux/openat2.h>
#endif
#else
struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};
#endif

#endif
