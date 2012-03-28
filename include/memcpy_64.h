#ifndef __MEMCPY_64_H__
#define __MEMCPY_64_H__

#include "compiler.h"
#include "types.h"

static always_inline void *builtin_memcpy(void *to, const void *from, unsigned int n)
{
	int d0, d1, d2;
	asm volatile("rep ; movsl		\n"
		     "movl %4,%%ecx		\n"
		     "andl $3,%%ecx		\n"
		     "jz 1f			\n"
		     "rep ; movsb		\n"
		     "1:"
		     : "=&c" (d0), "=&D" (d1), "=&S" (d2)
		     : "0" (n / 4), "g" (n), "1" ((long)to), "2" ((long)from)
		     : "memory");
	return to;
}

#endif /* __MEMCPY_64_H__ */
