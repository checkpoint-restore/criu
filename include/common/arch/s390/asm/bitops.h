#ifndef _S390_BITOPS_H
#define _S390_BITOPS_H

#include "common/asm/bitsperlong.h"
#include "common/compiler.h"
#include "common/arch/s390/asm/atomic_ops.h"

#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_LONG)
#define __BITOPS_WORDS(bits)	(((bits) + BITS_PER_LONG - 1) / BITS_PER_LONG)

#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]

static inline unsigned long *
__bitops_word(unsigned long nr, volatile unsigned long *ptr)
{
	unsigned long addr;

	addr = (unsigned long)ptr + ((nr ^ (nr & (BITS_PER_LONG - 1))) >> 3);
	return (unsigned long *)addr;
}

static inline unsigned char *
__bitops_byte(unsigned long nr, volatile unsigned long *ptr)
{
	return ((unsigned char *)ptr) + ((nr ^ (BITS_PER_LONG - 8)) >> 3);
}

static inline void set_bit(unsigned long nr, volatile unsigned long *ptr)
{
	unsigned long *addr = __bitops_word(nr, ptr);
	unsigned long mask;

	mask = 1UL << (nr & (BITS_PER_LONG - 1));
	__atomic64_or((long) mask, (long *) addr);
}

static inline void clear_bit(unsigned long nr, volatile unsigned long *ptr)
{
	unsigned long *addr = __bitops_word(nr, ptr);
	unsigned long mask;

	mask = ~(1UL << (nr & (BITS_PER_LONG - 1)));
	__atomic64_and((long) mask, (long *) addr);
}

static inline void change_bit(unsigned long nr, volatile unsigned long *ptr)
{
	unsigned long *addr = __bitops_word(nr, ptr);
	unsigned long mask;

	mask = 1UL << (nr & (BITS_PER_LONG - 1));
	__atomic64_xor((long) mask, (long *) addr);
}

static inline int
test_and_set_bit(unsigned long nr, volatile unsigned long *ptr)
{
	unsigned long *addr = __bitops_word(nr, ptr);
	unsigned long old, mask;

	mask = 1UL << (nr & (BITS_PER_LONG - 1));
	old = __atomic64_or_barrier((long) mask, (long *) addr);
	return (old & mask) != 0;
}

static inline int test_bit(unsigned long nr, const volatile unsigned long *ptr)
{
	const volatile unsigned char *addr;

	addr = ((const volatile unsigned char *)ptr);
	addr += (nr ^ (BITS_PER_LONG - 8)) >> 3;
	return (*addr >> (nr & 7)) & 1;
}

static inline unsigned char __flogr(unsigned long word)
{
	if (__builtin_constant_p(word)) {
		unsigned long bit = 0;

		if (!word)
			return 64;
		if (!(word & 0xffffffff00000000UL)) {
			word <<= 32;
			bit += 32;
		}
		if (!(word & 0xffff000000000000UL)) {
			word <<= 16;
			bit += 16;
		}
		if (!(word & 0xff00000000000000UL)) {
			word <<= 8;
			bit += 8;
		}
		if (!(word & 0xf000000000000000UL)) {
			word <<= 4;
			bit += 4;
		}
		if (!(word & 0xc000000000000000UL)) {
			word <<= 2;
			bit += 2;
		}
		if (!(word & 0x8000000000000000UL)) {
			word <<= 1;
			bit += 1;
		}
		return bit;
	} else {
		return __builtin_clzl(word);
	}
}

static inline unsigned long __ffs(unsigned long word)
{
	return __flogr(-word & word) ^ (BITS_PER_LONG - 1);
}

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))

static inline unsigned long _find_next_bit(const unsigned long *addr,
				    unsigned long nbits, unsigned long start,
				    unsigned long invert)
{
	unsigned long tmp;

	if (!nbits || start >= nbits)
		return nbits;

	tmp = addr[start / BITS_PER_LONG] ^ invert;

	tmp &= BITMAP_FIRST_WORD_MASK(start);
	start = round_down(start, BITS_PER_LONG);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= nbits)
			return nbits;

		tmp = addr[start / BITS_PER_LONG] ^ invert;
	}

	return min(start + __ffs(tmp), nbits);
}

static inline unsigned long find_next_bit(const unsigned long *addr,
					  unsigned long size,
					  unsigned long offset)
{
	return _find_next_bit(addr, size, offset, 0UL);
}

#define for_each_bit(i, bitmask)				\
	for (i = find_next_bit(bitmask, sizeof(bitmask), 0);	\
	     i < sizeof(bitmask);				\
	     i = find_next_bit(bitmask, sizeof(bitmask), i + 1))

#endif /* _S390_BITOPS_H */
