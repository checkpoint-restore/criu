#ifndef CR_BITOPS_H_
#define CR_BITOPS_H_

#ifdef CONFIG_X86_64

#define DIV_ROUND_UP(n,d)	(((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, 8 * sizeof(long))

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

static inline void set_bit(int nr, volatile unsigned long *addr)
{
	asm volatile("bts %1,%0" : ADDR : "Ir" (nr) : "memory");
}

static inline void change_bit(int nr, volatile unsigned long *addr)
{
	asm volatile("btc %1,%0" : ADDR : "Ir" (nr));
}

static inline int test_bit(int nr, volatile const unsigned long *addr)
{
	int oldbit;

	asm volatile("bt %2,%1\n\t"
		     "sbb %0,%0"
		     : "=r" (oldbit)
		     : "m" (*(unsigned long *)addr), "Ir" (nr));

	return oldbit;
}

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
	asm volatile("btr %1,%0" : ADDR : "Ir" (nr));
}

#else /* CONFIG_X86_64 */
# error x86-32 is not implemented yet
#endif /* CONFIG_X86_64 */

#endif /* CR_BITOPS_H_ */
