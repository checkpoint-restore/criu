#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "asm/types.h"
#include "asm/prlimit.h"

#include "compiler.h"
#include "config.h"

#ifndef CONFIG_HAS_PRLIMIT

#ifndef RLIM64_INFINITY
# define RLIM64_INFINITY	(~0ULL)
#endif

int prlimit(pid_t pid, int resource, const struct rlimit *new_rlimit, struct rlimit *old_rlimit)
{
	struct rlimit64 new_rlimit64_mem;
	struct rlimit64 old_rlimit64_mem;
	struct rlimit64 *new_rlimit64 = NULL;
	struct rlimit64 *old_rlimit64 = NULL;
	int ret;

	if (old_rlimit)
		old_rlimit64 = &old_rlimit64_mem;

	if (new_rlimit) {
		if (new_rlimit->rlim_cur == RLIM_INFINITY)
			new_rlimit64_mem.rlim_cur = RLIM64_INFINITY;
		else
			new_rlimit64_mem.rlim_cur = new_rlimit->rlim_cur;
		if (new_rlimit->rlim_max == RLIM_INFINITY)
			new_rlimit64_mem.rlim_max = RLIM64_INFINITY;
		else
			new_rlimit64_mem.rlim_max = new_rlimit->rlim_max;
		new_rlimit64 = &new_rlimit64_mem;
	}

	ret = sys_prlimit64(pid, resource, new_rlimit64, old_rlimit64);

	if (ret == 0 && old_rlimit) {
		old_rlimit->rlim_cur = old_rlimit64_mem.rlim_cur;
		if (old_rlimit->rlim_cur != old_rlimit64_mem.rlim_cur) {
			if (new_rlimit) {
				errno = EOVERFLOW;
				return -1;
			}
			old_rlimit->rlim_cur = RLIM_INFINITY;
		}
		old_rlimit->rlim_max = old_rlimit64_mem.rlim_max;
		if (old_rlimit->rlim_max != old_rlimit64_mem.rlim_max) {
			if (new_rlimit) {
				errno = EOVERFLOW;
				return -1;
			}
			old_rlimit->rlim_max = RLIM_INFINITY;
		}
	} else if (ret) {
		errno = -ret;
		ret = -1;
	}

	return ret;
}

#endif /* CONFIG_HAS_PRLIMIT */
