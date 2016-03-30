#ifndef __CR_ASM_GENERIC_STRING_H__
#define __CR_ASM_GENERIC_STRING_H__

#include "compiler.h"

#ifndef HAS_BUILTIN_MEMCPY
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

#ifndef HAS_BUILTIN_MEMCMP
static always_inline int builtin_memcmp(const void *cs, const void *ct, size_t count)
{
	const unsigned char *su1, *su2;
	int res = 0;

	for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
		if ((res = *su1 - *su2) != 0)
			break;
	return res;
}
#endif

#ifndef HAS_BUILTIN_STRNCMP
static always_inline int builtin_strncmp(const char *cs, const char *ct, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (cs[i] != ct[i])
			return cs[i] < ct[i] ? -1 : 1;
		if (!cs[i])
			break;
	}
	return 0;
}
#endif

#endif /* __CR_ASM_GENERIC_STRING_H__ */
