#ifndef __CR_ASM_STRING_H__
#define __CR_ASM_STRING_H__

#define HAS_BUILTIN_MEMCPY

#include "common/compiler.h"
#include "asm-generic/string.h"

#ifdef CR_NOGLIBC
extern void *memcpy_x86(void *to, const void *from, size_t n);
static inline void *builtin_memcpy(void *to, const void *from, size_t n)
{
	if (n)
		memcpy_x86(to, from, n);
	return to;
}
#else
#define builtin_memcpy memcpy
#endif /* CR_NOGLIBC */

#endif /* __CR_ASM_STRING_H__ */
