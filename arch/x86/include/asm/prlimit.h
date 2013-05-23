#ifndef __CR_PRLIMIT_H__
#define __CR_PRLIMIT_H__

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "config.h"

#ifndef CONFIG_HAS_PRLIMIT
extern int prlimit(pid_t pid, int resource, const struct rlimit *new_rlimit, struct rlimit *old_rlimit);
#endif

#endif /* __CR_PRLIMIT_H__ */
