/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 1994-1997, 99, 2000, 06, 07 Ralf Baechle (ralf@linux-mips.org)
 * Copyright (c) 1999, 2000  Silicon Graphics, Inc.
 */
/* #include <linux/bitops.h> */
/* #include <linux/irqflags.h> */
/* #include <linux/export.h> */
//#include "common/arch/mips/asm/bitops_mips.h"
#include "bitops.h"

/**
 * __mips_set_bit - Atomically set a bit in memory.  This is called by
 * set_bit() if it cannot find a faster solution.
 * @nr: the bit to set
 * @addr: the address to start counting from
 */
void __mips_set_bit(unsigned long nr, volatile unsigned long *addr)
{
	unsigned long *a = (unsigned long *)addr;
	unsigned bit = nr & SZLONG_MASK;
	unsigned long mask;
	unsigned long flags;

	a += nr >> SZLONG_LOG;
	mask = 1UL << bit;
	raw_local_irq_save(flags);
	*a |= mask;
	raw_local_irq_restore(flags);
}
//EXPORT_SYMBOL(__mips_set_bit);


/**
 * __mips_clear_bit - Clears a bit in memory.  This is called by clear_bit() if
 * it cannot find a faster solution.
 * @nr: Bit to clear
 * @addr: Address to start counting from
 */
void __mips_clear_bit(unsigned long nr, volatile unsigned long *addr)
{
	unsigned long *a = (unsigned long *)addr;
	unsigned bit = nr & SZLONG_MASK;
	unsigned long mask;
	unsigned long flags;

	a += nr >> SZLONG_LOG;
	mask = 1UL << bit;
	raw_local_irq_save(flags);
	*a &= ~mask;
	raw_local_irq_restore(flags);
}
//EXPORT_SYMBOL(__mips_clear_bit);


/**
 * __mips_change_bit - Toggle a bit in memory.	This is called by change_bit()
 * if it cannot find a faster solution.
 * @nr: Bit to change
 * @addr: Address to start counting from
 */
void __mips_change_bit(unsigned long nr, volatile unsigned long *addr)
{
	unsigned long *a = (unsigned long *)addr;
	unsigned bit = nr & SZLONG_MASK;
	unsigned long mask;
	unsigned long flags;

	a += nr >> SZLONG_LOG;
	mask = 1UL << bit;
	raw_local_irq_save(flags);
	*a ^= mask;
	raw_local_irq_restore(flags);
}
//EXPORT_SYMBOL(__mips_change_bit);


/**
 * __mips_test_and_set_bit - Set a bit and return its old value.  This is
 * called by test_and_set_bit() if it cannot find a faster solution.
 * @nr: Bit to set
 * @addr: Address to count from
 */
int __mips_test_and_set_bit(unsigned long nr,
			    volatile unsigned long *addr)
{
	unsigned long *a = (unsigned long *)addr;
	unsigned bit = nr & SZLONG_MASK;
	unsigned long mask;
	unsigned long flags;
	int res;

	a += nr >> SZLONG_LOG;
	mask = 1UL << bit;
	raw_local_irq_save(flags);
	res = (mask & *a) != 0;
	*a |= mask;
	raw_local_irq_restore(flags);
	return res;
}
//EXPORT_SYMBOL(__mips_test_and_set_bit);


/**
 * __mips_test_and_set_bit_lock - Set a bit and return its old value.  This is
 * called by test_and_set_bit_lock() if it cannot find a faster solution.
 * @nr: Bit to set
 * @addr: Address to count from
 */
int __mips_test_and_set_bit_lock(unsigned long nr,
				 volatile unsigned long *addr)
{
	unsigned long *a = (unsigned long *)addr;
	unsigned bit = nr & SZLONG_MASK;
	unsigned long mask;
	unsigned long flags;
	int res;

	a += nr >> SZLONG_LOG;
	mask = 1UL << bit;
	raw_local_irq_save(flags);
	res = (mask & *a) != 0;
	*a |= mask;
	raw_local_irq_restore(flags);
	return res;
}
//EXPORT_SYMBOL(__mips_test_and_set_bit_lock);


/**
 * __mips_test_and_clear_bit - Clear a bit and return its old value.  This is
 * called by test_and_clear_bit() if it cannot find a faster solution.
 * @nr: Bit to clear
 * @addr: Address to count from
 */
int __mips_test_and_clear_bit(unsigned long nr, volatile unsigned long *addr)
{
	unsigned long *a = (unsigned long *)addr;
	unsigned bit = nr & SZLONG_MASK;
	unsigned long mask;
	unsigned long flags;
	int res;

	a += nr >> SZLONG_LOG;
	mask = 1UL << bit;
	raw_local_irq_save(flags);
	res = (mask & *a) != 0;
	*a &= ~mask;
	raw_local_irq_restore(flags);
	return res;
}
//EXPORT_SYMBOL(__mips_test_and_clear_bit);


/**
 * __mips_test_and_change_bit - Change a bit and return its old value.	This is
 * called by test_and_change_bit() if it cannot find a faster solution.
 * @nr: Bit to change
 * @addr: Address to count from
 */
int __mips_test_and_change_bit(unsigned long nr, volatile unsigned long *addr)
{
	unsigned long *a = (unsigned long *)addr;
	unsigned bit = nr & SZLONG_MASK;
	unsigned long mask;
	unsigned long flags;
	int res;

	a += nr >> SZLONG_LOG;
	mask = 1UL << bit;
	raw_local_irq_save(flags);
	res = (mask & *a) != 0;
	*a ^= mask;
	raw_local_irq_restore(flags);
	return res;
}
//EXPORT_SYMBOL(__mips_test_and_change_bit);


#define BITOP_WORD(nr)		((nr) / BITS_PER_LONG)

#ifndef find_next_bit
/*
 * fixme: gysun 
 * from kernel/linux-3.10.84/lib/find_next_bit.c
 */
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
//EXPORT_SYMBOL(find_next_bit);
#endif
