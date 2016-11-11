#ifndef __CR_ASM_GENERIC_STRING_H__
#define __CR_ASM_GENERIC_STRING_H__

#include "common/compiler.h"

/* C compiler may generate calls to memcmp, memset, memcpy and memmove,
 * so it relies on those to be available during linking.
 * In case we are not linking our code against glibc, we set CR_NOGLIBC
 * and have to provide our own implementations of mem*() functions.
 *
 * For now, not having memmove() seems OK for both gcc and clang.
 */

#ifndef HAS_BUILTIN_MEMCPY
static __maybe_unused void *builtin_memcpy(void *to, const void *from, size_t n)
{
	size_t i;
	unsigned char *cto = to;
	const unsigned char *cfrom = from;

	for (i = 0; i < n; ++i, ++cto, ++cfrom) {
		*cto = *cfrom;
	}

	return to;
}
#ifdef CR_NOGLIBC
void *memcpy(void *to, const void *from, size_t n)	\
	     __attribute__ ((weak, alias ("builtin_memcpy")));
#endif
#endif

#ifndef HAS_BUILTIN_MEMCMP
static __maybe_unused int builtin_memcmp(const void *cs, const void *ct, size_t count)
{
	const unsigned char *su1, *su2;
	int res = 0;

	for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
		if ((res = *su1 - *su2) != 0)
			break;
	return res;
}
#ifdef CR_NOGLIBC
int memcmp(const void *cs, const void *ct, size_t count)	\
	     __attribute__ ((weak, alias ("builtin_memcmp")));
#endif
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

#ifndef HAS_BUILTIN_MEMSET
static __maybe_unused void *builtin_memset(void *s, const int c, size_t count)
{
	char *dest = s;
	size_t i = 0;

	while (i < count)
		dest[i++] = (char) c;

	return s;
}
#ifdef CR_NOGLIBC
void *memset(void *s, const int c, size_t count)	\
	     __attribute__ ((weak, alias ("builtin_memset")));
#endif
#endif

#endif /* __CR_ASM_GENERIC_STRING_H__ */
