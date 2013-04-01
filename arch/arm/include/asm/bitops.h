#ifndef __CR_BITOPS_H__
#define __CR_BITOPS_H__

#include "asm/bitsperlong.h"

#define DIV_ROUND_UP(n,d)	(((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_LONG)

#define DECLARE_BITMAP(name, bits)		\
	unsigned long name[BITS_TO_LONGS(bits)]

#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 1)
/* Technically wrong, but this avoids compilation errors on some gcc
   versions. */
#define BITOP_ADDR(x) "=m" (*(volatile long *) (x))
#else
#define BITOP_ADDR(x) "+m" (*(volatile long *) (x))
#endif

#define ADDR				BITOP_ADDR(addr)

static inline void set_bit(int nr, volatile unsigned long *addr) {
	*addr |= (1 << nr);
}

static inline void change_bit(int nr, volatile unsigned long *addr)
{
	*addr ^= (1 << nr);
}

static inline int test_bit(int nr, volatile const unsigned long *addr)
{
	return (*addr & (1 << nr)) ? -1 : 0;
}

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
	*addr &= ~(1 << nr);
}

/**
 * __ffs - find first set bit in word
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static inline unsigned long __ffs(unsigned long word)
{
	int p = 0;

	for (; p < 8*sizeof(word); ++p) {
		if (word & 1) {
			break;
		}

		word >>= 1;
	}

	return p;
}

#define BITOP_WORD(nr)		((nr) / BITS_PER_LONG)

/*
 * Find the next set bit in a memory region.
 */
static inline
unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
			    unsigned long offset)
{
	const unsigned long *p = addr + BITOP_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
		tmp &= (~0UL << offset);
		if (size < BITS_PER_LONG)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG-1)) {
		if ((tmp = *(p++)))
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp &= (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)		/* Are any bits set? */
		return result + size;	/* Nope. */
found_middle:
	return result + __ffs(tmp);
}

#define for_each_bit(i, bitmask)				\
	for (i = find_next_bit(bitmask, sizeof(bitmask), 0);	\
	     i < sizeof(bitmask);				\
	     i = find_next_bit(bitmask, sizeof(bitmask), i + 1))

#endif /* __CR_BITOPS_H__ */
