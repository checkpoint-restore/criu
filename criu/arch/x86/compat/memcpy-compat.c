#include <stddef.h>

/*
 * This provides an optimized implementation of memcpy, and a simplified
 * implementation of memset and memmove. These are used here because the
 * standard kernel runtime versions are not yet available and we don't
 * trust the gcc built-in implementations as they may do unexpected things
 * (e.g. FPU ops) in the minimal decompression stub execution environment.
 *
 * From Linux kernel boot helpers: arch/x86/boot/compressed/string.c
 */

void *memcpy_x86(void *dest, const void *src, size_t n)
{
	int d0, d1, d2;
	asm volatile(
		"rep ; movsl\n\t"
		"movl %4,%%ecx\n\t"
		"rep ; movsb\n\t"
		: "=&c" (d0), "=&D" (d1), "=&S" (d2)
		: "0" (n >> 2), "g" (n & 3), "1" (dest), "2" (src)
		: "memory");

	return dest;
}
