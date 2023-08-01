#ifndef __CR_ASM_BITOPS_H__
#define __CR_ASM_BITOPS_H__

#include "common/compiler.h"
#include "common/asm-generic/bitops.h"

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
