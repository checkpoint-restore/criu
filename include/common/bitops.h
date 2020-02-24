#ifndef __CR_COMMON_BITOPS_H__
#define __CR_COMMON_BITOPS_H__
#include "common/asm/bitops.h"

#include "common/bitsperlong.h"
#include <endian.h>

#if __BYTE_ORDER == __BIG_ENDIAN
#define BITOP_LE_SWIZZLE	((BITS_PER_LONG-1) & ~0x7)
#else
#define BITOP_LE_SWIZZLE	0
#endif

static inline int test_and_set_bit_le(int nr, void *addr)
{
	return test_and_set_bit(nr ^ BITOP_LE_SWIZZLE, addr);
}

static inline void clear_bit_le(int nr, void *addr)
{
	clear_bit(nr ^ BITOP_LE_SWIZZLE, addr);
}

/**
 * fls - find last (most-significant) bit set
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 */
static inline int fls(unsigned int x)
{
	int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

/**
 * fls64 - find last set bit in a 64-bit word
 * @x: the word to search
 *
 * This is defined in a similar way as the libc and compiler builtin
 * ffsll, but returns the position of the most significant set bit.
 *
 * fls64(value) returns 0 if value is 0 or the position of the last
 * set bit if value is nonzero. The last (most significant) bit is
 * at position 64.
 */
#if BITS_PER_LONG == 32
static inline int fls64(uint64_t x)
{
	uint32_t h = x >> 32;
	if (h)
		return fls(h) + 32;
	return fls(x);
}
#elif BITS_PER_LONG == 64
static inline int fls64(uint64_t x)
{
	if (x == 0)
		return 0;
	return __fls(x) + 1;
}
#else
#error BITS_PER_LONG not 32 or 64
#endif
#endif
