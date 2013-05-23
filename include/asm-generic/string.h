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

#ifndef HAS_BUILTIN_STRCMP
static always_inline int builtin_strcmp(const char *cs, const char *ct)
{
	unsigned char c1, c2;

	while (1) {
		c1 = *cs++;
		c2 = *ct++;
		if (c1 != c2)
			return c1 < c2 ? -1 : 1;
		if (!c1)
			break;
	}
	return 0;
}
#endif

#endif /* __CR_ASM_GENERIC_STRING_H__ */
