#ifndef __CR_ASM_STRING_H__
#define __CR_ASM_STRING_H__

#include "common/compiler.h"

#define HAS_BUILTIN_MEMCPY
#define HAS_BUILTIN_MEMCMP

#include "asm-generic/string.h"

#ifdef CR_NOGLIBC
extern void memcpy_power7(void *to, const void *from, unsigned long n);
static inline void *builtin_memcpy(void *to, const void *from, unsigned long n)
{
	if (n)
		memcpy_power7(to, from, n);
	return to;
}
extern int builtin_memcmp(const void *cs, const void *ct, size_t count);
#else
/*
 * When building with the C library, call its services
 */
#define builtin_memcpy memcpy
#define builtin_memcmp memcmp
#endif

#endif /* __CR_ASM_STRING_H__ */
