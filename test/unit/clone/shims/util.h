#ifndef __CR_UTIL_SHIM_H__
#define __CR_UTIL_SHIM_H__

#include <sys/types.h>

static inline void print_stack_trace(pid_t pid)
{
	(void)pid;
}

#endif /* __CR_UTIL_SHIM_H__ */
