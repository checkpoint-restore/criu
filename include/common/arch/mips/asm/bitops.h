#ifndef _LINUX_BITOPS_H
#define _LINUX_BITOPS_H
#include <asm/types.h>
#include "common/compiler.h"
#include "common/asm-generic/bitops.h"

/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */

static inline int test_and_set_bit(unsigned long nr,
	volatile unsigned long *addr)
{
	unsigned long *m = ((unsigned long *) addr) + (nr >> 6);
	unsigned long temp = 0;
	unsigned long res;
	int bit = nr & 63UL;

	do {
	    __asm__ __volatile__(
				 "	.set	mips3				\n"
				 "	lld     %0, %1	# test_and_set_bit	\n"
				 "	or	%2, %0, %3			\n"
				 "	scd	%2, %1				\n"
				 "	.set	mips0				\n"
				 : "=&r" (temp), "+m" (*m), "=&r" (res)
				 : "r" (1UL << bit)
				 : "memory");
	} while (unlikely(!res));

	res = temp & (1UL << bit);

	return res != 0;
}

#endif
