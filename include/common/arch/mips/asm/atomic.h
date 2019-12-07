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
#define atomic_read(v)		(*(volatile int *)&(v)->counter)

/*
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
#if defined(CONFIG_CPU_LOONGSON3) || defined(CONFIG_CPU_LOONGSON2K)
static __inline__ void atomic_set(atomic_t * v, int i)
{
		__asm__ __volatile__(
		"	.set    mips64r2	# atomic_set		\n"
                "	.set    noreorder				\n"
		"	sync						\n"
		"	sw      %1, %0					\n"
		"	sync						\n"
		"	.set    reorder					\n"
		"	.set    mips0					\n"
		: "+m" (v->counter)
		: "r" (i));
}
#else
#define atomic_set(v, i)		((v)->counter = (i))
#endif
/*
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */

static __inline__ void atomic_add(int i, atomic_t * v)
{
	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		int temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%0, %1		# atomic_add		\n"
		"	addu	%0, %2					\n"
		"	sc	%0, %1					\n"
		"	beqzl	%0, 1b					\n"
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc && LOONGSON_LLSC_WAR) {
		int temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			__WEAK_LLSC_MB
			"	ll	%0, %1		# atomic_add	\n"
			"	addu	%0, %2				\n"
			"	sc	%0, %1				\n"
			"	.set	mips0				\n"
			: "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!temp));

		smp_llsc_mb();
	} else if (kernel_uses_llsc) {
		int temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	ll	%0, %1		# atomic_add	\n"
			"	addu	%0, %2				\n"
			"	sc	%0, %1				\n"
			"	.set	mips0				\n"
			: "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!temp));
	} else {
	    pr_err("ERROR:No implement!");
	}
}

/*
 * atomic_sub - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v.
 */
static __inline__ void atomic_sub(int i, atomic_t * v)
{
	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		int temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%0, %1		# atomic_sub		\n"
		"	subu	%0, %2					\n"
		"	sc	%0, %1					\n"
		"	beqzl	%0, 1b					\n"
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc && LOONGSON_LLSC_WAR) {
		int temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			__WEAK_LLSC_MB
			"	ll	%0, %1		# atomic_sub	\n"
			"	subu	%0, %2				\n"
			"	sc	%0, %1				\n"
			"	.set	mips0				\n"
			: "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!temp));

		smp_llsc_mb();
	} else if (kernel_uses_llsc) {
		int temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	ll	%0, %1		# atomic_sub	\n"
			"	subu	%0, %2				\n"
			"	sc	%0, %1				\n"
			"	.set	mips0				\n"
			: "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!temp));
	} else {
	    pr_err("ERROR:No implement!");
	}
}

/*
 * Same as above, but return the result value
 */
static __inline__ int atomic_add_return(int i, atomic_t * v)
{
	int result;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		int temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%1, %2		# atomic_add_return	\n"
		"	addu	%0, %1, %3				\n"
		"	sc	%0, %2					\n"
		"	beqzl	%0, 1b					\n"
		"	addu	%0, %1, %3				\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc && LOONGSON_LLSC_WAR) {
		int temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			__WEAK_LLSC_MB
			"	ll	%1, %2	# atomic_add_return	\n"
			"	addu	%0, %1, %3			\n"
			"	sc	%0, %2				\n"
			"	.set	mips0				\n"
			: "=&r" (result), "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!result));

		result = temp + i;
	} else if (kernel_uses_llsc) {
		int temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	ll	%1, %2	# atomic_add_return	\n"
			"	addu	%0, %1, %3			\n"
			"	sc	%0, %2				\n"
			"	.set	mips0				\n"
			: "=&r" (result), "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!result));

		result = temp + i;
	} else {
	    pr_err("ERROR:No implement!");
	}

	smp_llsc_mb();

	return result;
}

static __inline__ int atomic_sub_return(int i, atomic_t * v)
{
	int result;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		int temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%1, %2		# atomic_sub_return	\n"
		"	subu	%0, %1, %3				\n"
		"	sc	%0, %2					\n"
		"	beqzl	%0, 1b					\n"
		"	subu	%0, %1, %3				\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "=m" (v->counter)
		: "Ir" (i), "m" (v->counter)
		: "memory");

	} else if (kernel_uses_llsc && LOONGSON_LLSC_WAR) {
		int temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			__WEAK_LLSC_MB
			"	ll	%1, %2	# atomic_sub_return	\n"
			"	subu	%0, %1, %3			\n"
			"	sc	%0, %2				\n"
			"	.set	mips0				\n"
			: "=&r" (result), "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!result));

		result = temp - i;
	} else if (kernel_uses_llsc) {
		int temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	ll	%1, %2	# atomic_sub_return	\n"
			"	subu	%0, %1, %3			\n"
			"	sc	%0, %2				\n"
			"	.set	mips0				\n"
			: "=&r" (result), "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!result));

		result = temp - i;
	} else {
	    pr_err("ERROR:No implement!");
	}

	smp_llsc_mb();

	return result;
}

#define atomic_cmpxchg(v, o, n) (cmpxchg(&((v)->counter), (o), (n)))
#define atomic_dec_return(v) atomic_sub_return(1, (v))
#define atomic_inc_return(v) atomic_add_return(1, (v))

/*
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
#define atomic_inc( v) atomic_add(1, (v))

/*
 * atomic_dec - decrement and test
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1.
 */
#define atomic_dec(v) atomic_sub(1, (v))

#endif /* __CR_ATOMIC_H__ */
