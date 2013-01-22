#ifndef __MEMCPY_ARM_H__
#define __MEMCPY_ARM_H__

#include "compiler.h"
#include "types.h"

static always_inline void *builtin_memcpy(void *to, const void *from, unsigned int n)
{
	int i;
	unsigned char *cto = to;
	const unsigned char *cfrom = from;

	for (i = 0; i < n; ++i, ++cto, ++cfrom) {
		*cto = *cfrom;
	}

	return to;
}

#endif
