#ifndef __CR_OPENAT2_H__
#define __CR_OPENAT2_H__

#include <unistd.h>

#include <compel/plugins/std/syscall-codes.h>

#include "linux/openat2.h"

#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV 0x01 /* Block mount-point crossings (includes bind-mounts). */
#endif
#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS 0x02 /* Block traversal through procfs-style "magic-links". */
#endif
#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS 0x04 /* Block traversal through all symlinks (implies RESOLVE_NO_MAGICLINKS). */
#endif
#ifndef RESOLVE_BENEATH
#define RESOLVE_BENEATH 0x08 /* Block "lexical" trickery like "..", symlinks, and absolute paths which escape the dirfd. */
#endif

/*
 * Don't put this into linux/openat2.h: glibc's fcntl.h includes
 * <linux/openat2.h>, which resolves to criu/include/linux/openat2.h, and
 * this wrapper conflicts with the sys_openat2 declaration of compel in PIE
 * code.
 */
static inline long sys_openat2(int dirfd, const char *pathname, struct open_how *how, size_t size)
{
	return syscall(__NR_openat2, dirfd, pathname, how, size);
}

#endif /* __CR_OPENAT2_H__ */
