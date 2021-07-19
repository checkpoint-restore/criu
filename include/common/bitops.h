#ifndef __CR_COMMON_BITOPS_H__
#define __CR_COMMON_BITOPS_H__
#include "common/asm/bitops.h"

#include "common/bitsperlong.h"
#include <endian.h>

#if __BYTE_ORDER == __BIG_ENDIAN
#define BITOP_LE_SWIZZLE ((BITS_PER_LONG - 1) & ~0x7)
#else
#define BITOP_LE_SWIZZLE 0
#endif

static inline int test_and_set_bit_le(int nr, void *addr)
{
	return test_and_set_bit(nr ^ BITOP_LE_SWIZZLE, addr);
}

static inline void clear_bit_le(int nr, void *addr)
{
	clear_bit(nr ^ BITOP_LE_SWIZZLE, addr);
}
#endif
