#ifndef __CR_ASM_BITOPS_H__
#define __CR_ASM_BITOPS_H__

#include "common/compiler.h"
#include "common/asm/bitsperlong.h"

#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define BITS_TO_LONGS(nr)  DIV_ROUND_UP(nr, BITS_PER_LONG)

#define DECLARE_BITMAP(name, bits) unsigned long name[BITS_TO_LONGS(bits)]
#define BITMAP_SIZE(name)	   (sizeof(name) * CHAR_BIT)

#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 1)
/* Technically wrong, but this avoids compilation errors on some gcc
   versions. */
#define BITOP_ADDR(x) "=m"(*(volatile long *)(x))
#else
#define BITOP_ADDR(x) "+m"(*(volatile long *)(x))
#endif

#define ADDR BITOP_ADDR(addr)

static inline void set_bit(int nr, volatile unsigned long *addr)
{
	addr += nr / BITS_PER_LONG;
	*addr |= (1UL << (nr % BITS_PER_LONG));
}

static inline void change_bit(int nr, volatile unsigned long *addr)
{
	addr += nr / BITS_PER_LONG;
	*addr ^= (1UL << (nr % BITS_PER_LONG));
}

static inline int test_bit(int nr, volatile const unsigned long *addr)
{
	addr += nr / BITS_PER_LONG;
	return (*addr & (1UL << (nr % BITS_PER_LONG))) ? -1 : 0;
}

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
	addr += nr / BITS_PER_LONG;
	*addr &= ~(1UL << (nr % BITS_PER_LONG));
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

#define BITOP_WORD(nr) ((nr) / BITS_PER_LONG)

/*
 * Find the next set bit in a memory region.
 */
static inline unsigned long find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset)
{
	const unsigned long *p = addr + BITOP_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG - 1);
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
	while (size & ~(BITS_PER_LONG - 1)) {
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
	if (tmp == 0UL)		      /* Are any bits set? */
		return result + size; /* Nope. */
found_middle:
	return result + __ffs(tmp);
}

#define for_each_bit(i, bitmask)                                                            \
	for (i = find_next_bit(bitmask, BITMAP_SIZE(bitmask), 0); i < BITMAP_SIZE(bitmask); \
	     i = find_next_bit(bitmask, BITMAP_SIZE(bitmask), i + 1))


#define BITS_PER_LONG 64

#define BIT_MASK(nr) ((1##UL) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)

#define __AMO(op) "amo" #op ".d"

#define __test_and_op_bit_ord(op, mod, nr, addr, ord)                        \
	({                                                                   \
		unsigned long __res, __mask;                                 \
		__mask = BIT_MASK(nr);                                       \
		__asm__ __volatile__(__AMO(op) #ord " %0, %2, %1"            \
				     : "=r"(__res), "+A"(addr[BIT_WORD(nr)]) \
				     : "r"(mod(__mask))                      \
				     : "memory");                            \
		((__res & __mask) != 0);                                     \
	})

#define __op_bit_ord(op, mod, nr, addr, ord)                \
	__asm__ __volatile__(__AMO(op) #ord " zero, %1, %0" \
			     : "+A"(addr[BIT_WORD(nr)])     \
			     : "r"(mod(BIT_MASK(nr)))       \
			     : "memory");

#define __test_and_op_bit(op, mod, nr, addr) __test_and_op_bit_ord(op, mod, nr, addr, .aqrl)
#define __op_bit(op, mod, nr, addr)	     __op_bit_ord(op, mod, nr, addr, )

/* Bitmask modifiers */
#define __NOP(x) (x)
#define __NOT(x) (~(x))

/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation may be reordered on other architectures than x86.
 */
static inline int test_and_set_bit(int nr, volatile unsigned long *addr)
{
	return __test_and_op_bit(or, __NOP, nr, addr);
}

#endif /* __CR_ASM_BITOPS_H__ */
