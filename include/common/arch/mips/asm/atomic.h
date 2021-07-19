#ifndef __CR_ATOMIC_H__
#define __CR_ATOMIC_H__

#include <linux/types.h>
#include "common/compiler.h"
#include "common/arch/mips/asm/utils.h"
#include "common/arch/mips/asm/cmpxchg.h"

/*
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically reads the value of @v.
 */
#define atomic_read(v) (*(volatile int *)&(v)->counter)

/*
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
#define atomic_set(v, i) ((v)->counter = (i))
/*
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */

static __inline__ void atomic_add(int i, atomic_t *v)
{
	int temp;

	do {
		__asm__ __volatile__("	.set	mips3				\n"
				     "	ll	%0, %1		# atomic_add	\n"
				     "	addu	%0, %2				\n"
				     "	sc	%0, %1				\n"
				     "	.set	mips0				\n"
				     : "=&r"(temp), "+m"(v->counter)
				     : "Ir"(i));
	} while (unlikely(!temp));
}

/*
 * atomic_sub - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v.
 */
static __inline__ void atomic_sub(int i, atomic_t *v)
{
	int temp;

	do {
		__asm__ __volatile__("	.set	mips3				\n"
				     "	ll	%0, %1		# atomic_sub	\n"
				     "	subu	%0, %2				\n"
				     "	sc	%0, %1				\n"
				     "	.set	mips0				\n"
				     : "=&r"(temp), "+m"(v->counter)
				     : "Ir"(i));
	} while (unlikely(!temp));
}

/*
 * Same as above, but return the result value
 */
static __inline__ int atomic_add_return(int i, atomic_t *v)
{
	int result;

	smp_mb__before_llsc();

	int temp;

	do {
		__asm__ __volatile__("	.set	mips3				\n"
				     "	ll	%1, %2	# atomic_add_return	\n"
				     "	addu	%0, %1, %3			\n"
				     "	sc	%0, %2				\n"
				     "	.set	mips0				\n"
				     : "=&r"(result), "=&r"(temp), "+m"(v->counter)
				     : "Ir"(i));
	} while (unlikely(!result));

	result = temp + i;

	smp_llsc_mb();

	return result;
}

static __inline__ int atomic_sub_return(int i, atomic_t *v)
{
	int result;

	smp_mb__before_llsc();

	int temp;

	do {
		__asm__ __volatile__("	.set	mips3				\n"
				     "	ll	%1, %2	# atomic_sub_return	\n"
				     "	subu	%0, %1, %3			\n"
				     "	sc	%0, %2				\n"
				     "	.set	mips0				\n"
				     : "=&r"(result), "=&r"(temp), "+m"(v->counter)
				     : "Ir"(i));
	} while (unlikely(!result));

	result = temp - i;

	smp_llsc_mb();

	return result;
}

#define atomic_cmpxchg(v, o, n) (cmpxchg(&((v)->counter), (o), (n)))
#define atomic_dec_return(v)	atomic_sub_return(1, (v))
#define atomic_inc_return(v)	atomic_add_return(1, (v))

/*
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
#define atomic_inc(v) atomic_add(1, (v))

/*
 * atomic_dec - decrement and test
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1.
 */
#define atomic_dec(v) atomic_sub(1, (v))

#endif /* __CR_ATOMIC_H__ */
