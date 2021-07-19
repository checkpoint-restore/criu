#ifndef __CR_BITOPS_H__
#define __CR_BITOPS_H__
/*
 * PowerPC atomic bit operations.
 *
 * Merged version by David Gibson <david@gibson.dropbear.id.au>.
 * Based on ppc64 versions by: Dave Engebretsen, Todd Inglett, Don
 * Reed, Pat McCarthy, Peter Bergner, Anton Blanchard.  They
 * originally took it from the ppc32 code.
 *
 * Within a word, bits are numbered LSB first.  Lot's of places make
 * this assumption by directly testing bits with (val & (1<<nr)).
 * This can cause confusion for large (> 1 word) bitmaps on a
 * big-endian system because, unlike little endian, the number of each
 * bit depends on the word size.
 *
 * The bitop functions are defined to work on unsigned longs, so for a
 * ppc64 system the bits end up numbered:
 *   |63..............0|127............64|191...........128|255...........192|
 * and on ppc32:
 *   |31.....0|63....32|95....64|127...96|159..128|191..160|223..192|255..224|
 *
 * There are a few little-endian macros used mostly for filesystem
 * bitmaps, these work on similar bit arrays layouts, but
 * byte-oriented:
 *   |7...0|15...8|23...16|31...24|39...32|47...40|55...48|63...56|
 *
 * The main difference is that bit 3-5 (64b) or 3-4 (32b) in the bit
 * number field needs to be reversed compared to the big-endian bit
 * fields. This can be achieved by XOR with 0x38 (64b) or 0x18 (32b).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * --
 * Copied from the kernel file arch/powerpc/include/asm/bitops.h
 */

#include "common/compiler.h"

#include "common/asm/bitsperlong.h"

#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define BITS_TO_LONGS(nr)  DIV_ROUND_UP(nr, BITS_PER_LONG)

#define DECLARE_BITMAP(name, bits) unsigned long name[BITS_TO_LONGS(bits)]

#define __stringify_in_c(...) #__VA_ARGS__
#define stringify_in_c(...)   __stringify_in_c(__VA_ARGS__) " "

#define BIT_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)

/* PPC bit number conversion */
#define PPC_BITLSHIFT(be)   (BITS_PER_LONG - 1 - (be))
#define PPC_BIT(bit)	    (1UL << PPC_BITLSHIFT(bit))
#define PPC_BITMASK(bs, be) ((PPC_BIT(bs) - PPC_BIT(be)) | PPC_BIT(bs))

#define PPC_INST_LDARX 0x7c0000a8
#define ___PPC_RA(a)   (((a)&0x1f) << 16)
#define ___PPC_RB(b)   (((b)&0x1f) << 11)
#define ___PPC_RS(s)   (((s)&0x1f) << 21)
#define __PPC_EH(eh)   (((eh)&0x1) << 0)
#define ___PPC_RT(t)   ___PPC_RS(t)

#define PPC_LDARX(t, a, b, eh) \
	stringify_in_c(.long PPC_INST_LDARX | ___PPC_RT(t) | ___PPC_RA(a) | ___PPC_RB(b) | __PPC_EH(eh))
#define PPC_LLARX(t, a, b, eh) PPC_LDARX(t, a, b, eh)

/* clang-format off */
/* Macro for generating the ***_bits() functions */
#define DEFINE_BITOP(fn, op)			\
static __inline__ void fn(unsigned long mask,   \
                volatile unsigned long *_p)     \
{                                               \
        unsigned long old;                      \
        unsigned long *p = (unsigned long *)_p; \
        __asm__ __volatile__ (                  \
"1:	ldarx	%0,0,%3\n"			\
        stringify_in_c(op) "%0,%0,%2\n"		\
        "stdcx.	%0,0,%3\n"			\
        "bne- 1b\n"                             \
        : "=&r" (old), "+m" (*p)                \
        : "r" (mask), "r" (p)                   \
        : "cc", "memory");                      \
}
/* clang-format on */

DEFINE_BITOP(set_bits, or)
DEFINE_BITOP(clear_bits, andc)
DEFINE_BITOP(change_bits, xor)

static __inline__ void set_bit(int nr, volatile unsigned long *addr)
{
	set_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
}

static __inline__ void clear_bit(int nr, volatile unsigned long *addr)
{
	clear_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
}

static __inline__ void change_bit(int nr, volatile unsigned long *addr)
{
	change_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
}

static inline int test_bit(int nr, const volatile unsigned long *addr)
{
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG - 1)));
}

/* Like DEFINE_BITOP(), with changes to the arguments to 'op' and the output
 * operands. */
/* clang-format off */
#define DEFINE_TESTOP(fn, op, prefix, postfix, eh)	\
static __inline__ unsigned long fn(			\
		unsigned long mask,			\
		volatile unsigned long *_p)		\
{							\
	unsigned long old, t;				\
	unsigned long *p = (unsigned long *)_p;		\
	__asm__ __volatile__ (				\
	prefix						\
"1:"	PPC_LLARX(%0,0,%3,eh) "\n"			\
	stringify_in_c(op) "%1,%0,%2\n"			\
	"stdcx. %1,0,%3\n"				\
	"bne- 1b\n"					\
	postfix						\
	: "=&r" (old), "=&r" (t)			\
	: "r" (mask), "r" (p)				\
	: "cc", "memory");				\
	return (old & mask);				\
}
/* clang-format on */

DEFINE_TESTOP(test_and_set_bits, or, "\nLWSYNC\n", "\nsync\n", 0)

static __inline__ int test_and_set_bit(unsigned long nr, volatile unsigned long *addr)
{
	return test_and_set_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) != 0;
}

/*
 * Return the zero-based bit position (LE, not IBM bit numbering) of
 * the most significant 1-bit in a double word.
 */
static __inline__ __attribute__((const)) int __ilog2(unsigned long x)
{
	int lz;

	asm("cntlzd	%0,%1" : "=r"(lz) : "r"(x));
	return BITS_PER_LONG - 1 - lz;
}

static __inline__ unsigned long __ffs(unsigned long x)
{
	return __ilog2(x & -x);
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
	if (tmp == 0UL) /* Are any bits set? */
		return result + size; /* Nope. */
found_middle:
	return result + __ffs(tmp);
}

#define for_each_bit(i, bitmask)                                                  \
	for (i = find_next_bit(bitmask, sizeof(bitmask), 0); i < sizeof(bitmask); \
	     i = find_next_bit(bitmask, sizeof(bitmask), i + 1))

#endif /* __CR_BITOPS_H__ */
