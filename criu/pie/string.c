#include <string.h>
#include "features.h"

/* C compiler may generate calls to memcmp, memset, memcpy and memmove,
 * so it relies on those to be available during linking.
 * In case we are not linking our code against glibc, we set CR_NOGLIBC
 * and have to provide our own implementations of mem*() functions.
 *
 * For now, not having memmove() seems OK for both gcc and clang.
 */

#ifndef ARCH_HAS_MEMCPY
void *memcpy(void *to, const void *from, size_t n)
{
	size_t i;
	unsigned char *cto = to;
	const unsigned char *cfrom = from;

	for (i = 0; i < n; ++i, ++cto, ++cfrom)
		*cto = *cfrom;

	return to;
}
#endif

#ifndef ARCH_HAS_MEMCMP
int memcmp(const void *cs, const void *ct, size_t count)
{
	const unsigned char *su1, *su2;
	int res = 0;

	for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
		if ((res = *su1 - *su2) != 0)
			break;
	return res;
}
#endif

int builtin_strncmp(const char *cs, const char *ct, size_t count)
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

#ifndef ARCH_HAS_MEMSET
void *memset(void *s, const int c, size_t count)
{
	char *dest = s;
	size_t i = 0;

	while (i < count)
		dest[i++] = (char) c;

	return s;
}
#endif
