#ifndef __CR_ATOMIC_H__
#define __CR_ATOMIC_H__

/*fixme: gysun*/

/* * from kernel/linux-3.10.84/arch/mips/include/asm/atomic.h
*/

/* #include <linux/irqflags.h> */
#include <linux/types.h>
/* #include <asm/barrier.h> */
/* #include <asm/cpu-features.h> */
/* #include <asm/cmpxchg.h> */
/* #include <asm/war.h> */
#include "common/compiler.h"
#include "common/arch/mips/asm/utils.h"
#include "common/arch/mips/asm/cmpxchg.h"

#define ATOMIC_INIT(i)	  { (i) }

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
#if 0
		unsigned long flags;

		raw_local_irq_save(flags);
		v->counter += i;
		raw_local_irq_restore(flags);
#endif
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
#if 0
		unsigned long flags;

		raw_local_irq_save(flags);
		v->counter -= i;
		raw_local_irq_restore(flags);
#endif
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
#if 0
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result += i;
		v->counter = result;
		raw_local_irq_restore(flags);
#endif
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
#if 0
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result -= i;
		v->counter = result;
		raw_local_irq_restore(flags);
#endif
	}

	smp_llsc_mb();

	return result;
}

/*
 * atomic_sub_if_positive - conditionally subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically test @v and subtract @i if @v is greater or equal than @i.
 * The function returns the old value of @v minus @i.
 */
static __inline__ int atomic_sub_if_positive(int i, atomic_t * v)
{
	int result;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		int temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%1, %2		# atomic_sub_if_positive\n"
		"	subu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	sc	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqzl	%0, 1b					\n"
		"	 subu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i), "m" (v->counter)
		: "memory");
	} else if (kernel_uses_llsc && LOONGSON_LLSC_WAR) {
		int temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:				# atomic_sub_if_positive\n"
		__WEAK_LLSC_MB
		"	ll	%1, %2					\n"
		"	subu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	sc	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqz	%0, 1b					\n"
		"	 subu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		int temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	ll	%1, %2		# atomic_sub_if_positive\n"
		"	subu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	sc	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqz	%0, 1b					\n"
		"	 subu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else {
#if 0
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result -= i;
		if (result >= 0)
			v->counter = result;
		raw_local_irq_restore(flags);
#endif
	}

	smp_llsc_mb();

	return result;
}

#define atomic_cmpxchg(v, o, n) (cmpxchg(&((v)->counter), (o), (n)))
#define atomic_xchg(v, new) (xchg(&((v)->counter), (new)))

/**
 * __atomic_add_unless - add unless the number is a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns the old value of @v.
 */
static __inline__ int __atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old;
	c = atomic_read(v);
	for (;;) {
		if (unlikely(c == (u)))
			break;
		old = atomic_cmpxchg((v), c, c + (a));
		if (likely(old == c))
			break;
		c = old;
	}
	return c;
}

#define atomic_dec_return(v) atomic_sub_return(1, (v))
#define atomic_inc_return(v) atomic_add_return(1, (v))

/*
 * atomic_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
#define atomic_sub_and_test(i, v) (atomic_sub_return((i), (v)) == 0)

/*
 * atomic_inc_and_test - increment and test
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
#define atomic_inc_and_test(v) (atomic_inc_return(v) == 0)

/*
 * atomic_dec_and_test - decrement by 1 and test
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
#define atomic_dec_and_test(v) (atomic_sub_return(1, (v)) == 0)

/*
 * atomic_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer of type atomic_t
 */
#define atomic_dec_if_positive(v)	atomic_sub_if_positive(1, v)

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

/*
 * atomic_add_negative - add and test if negative
 * @v: pointer of type atomic_t
 * @i: integer value to add
 *
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */
#define atomic_add_negative(i, v) (atomic_add_return(i, (v)) < 0)

#if 0 //fixme: gsyun //#ifdef CONFIG_64BIT

#define ATOMIC64_INIT(i)    { (i) }

/*
 * atomic64_read - read atomic variable
 * @v: pointer of type atomic64_t
 *
 */
#define atomic64_read(v)	(*(volatile long *)&(v)->counter)

/*
 * atomic64_set - set atomic variable
 * @v: pointer of type atomic64_t
 * @i: required value
 */
#if defined(CONFIG_CPU_LOONGSON3) || defined(CONFIG_CPU_LOONGSON2K)
static __inline__ void atomic64_set(atomic64_t * v, long i)
{
		__asm__ __volatile__(
		"	.set    mips64r2	# atomic64_set		\n"
                "	.set    noreorder       		    	\n"
		"	sync						\n"
		"	sd      %1, %0					\n"
		"	sync						\n"
                "	.set    reorder				    	\n"
		"	.set    mips0					\n"
		: "+m" (v->counter)
		: "r" (i));
}
#else
#define atomic64_set(v, i)	((v)->counter = (i))
#endif

/*
 * atomic64_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic64_t
 *
 * Atomically adds @i to @v.
 */
static __inline__ void atomic64_add(long i, atomic64_t * v)
{
	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%0, %1		# atomic64_add		\n"
		"	daddu	%0, %2					\n"
		"	scd	%0, %1					\n"
		"	beqzl	%0, 1b					\n"
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc && LOONGSON_LLSC_WAR) {
		long temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			__WEAK_LLSC_MB
			"	lld	%0, %1		# atomic64_add	\n"
			"	daddu	%0, %2				\n"
			"	scd	%0, %1				\n"
			"	.set	mips0				\n"
			: "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!temp));

		smp_llsc_mb();
	} else if (kernel_uses_llsc) {
		long temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	lld	%0, %1		# atomic64_add	\n"
			"	daddu	%0, %2				\n"
			"	scd	%0, %1				\n"
			"	.set	mips0				\n"
			: "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!temp));
	} else {
#if 0
		unsigned long flags;

		raw_local_irq_save(flags);
		v->counter += i;
		raw_local_irq_restore(flags);
#endif
	}
}

/*
 * atomic64_sub - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic64_t
 *
 * Atomically subtracts @i from @v.
 */
static __inline__ void atomic64_sub(long i, atomic64_t * v)
{
	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%0, %1		# atomic64_sub		\n"
		"	dsubu	%0, %2					\n"
		"	scd	%0, %1					\n"
		"	beqzl	%0, 1b					\n"
		"	.set	mips0					\n"
		: "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc && LOONGSON_LLSC_WAR) {
		long temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			__WEAK_LLSC_MB
			"	lld	%0, %1		# atomic64_sub	\n"
			"	dsubu	%0, %2				\n"
			"	scd	%0, %1				\n"
			"	.set	mips0				\n"
			: "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!temp));

		smp_llsc_mb();
	} else if (kernel_uses_llsc) {
		long temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	lld	%0, %1		# atomic64_sub	\n"
			"	dsubu	%0, %2				\n"
			"	scd	%0, %1				\n"
			"	.set	mips0				\n"
			: "=&r" (temp), "+m" (v->counter)
			: "Ir" (i));
		} while (unlikely(!temp));
	} else {
#if 0
		unsigned long flags;

		raw_local_irq_save(flags);
		v->counter -= i;
		raw_local_irq_restore(flags);
#endif
	}
}

/*
 * Same as above, but return the result value
 */
static __inline__ long atomic64_add_return(long i, atomic64_t * v)
{
	long result;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%1, %2		# atomic64_add_return	\n"
		"	daddu	%0, %1, %3				\n"
		"	scd	%0, %2					\n"
		"	beqzl	%0, 1b					\n"
		"	daddu	%0, %1, %3				\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc && LOONGSON_LLSC_WAR) {
		long temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			__WEAK_LLSC_MB
			"	lld	%1, %2	# atomic64_add_return	\n"
			"	daddu	%0, %1, %3			\n"
			"	scd	%0, %2				\n"
			"	.set	mips0				\n"
			: "=&r" (result), "=&r" (temp), "=m" (v->counter)
			: "Ir" (i), "m" (v->counter)
			: "memory");
		} while (unlikely(!result));

		result = temp + i;
	} else if (kernel_uses_llsc) {
		long temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	lld	%1, %2	# atomic64_add_return	\n"
			"	daddu	%0, %1, %3			\n"
			"	scd	%0, %2				\n"
			"	.set	mips0				\n"
			: "=&r" (result), "=&r" (temp), "=m" (v->counter)
			: "Ir" (i), "m" (v->counter)
			: "memory");
		} while (unlikely(!result));

		result = temp + i;
	} else {
#if 0
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result += i;
		v->counter = result;
		raw_local_irq_restore(flags);
#endif
	}

	smp_llsc_mb();

	return result;
}

static __inline__ long atomic64_sub_return(long i, atomic64_t * v)
{
	long result;

#ifdef CONFIG_PHASE_LOCK
	unsigned long flags;

	flags = loongson3_phase_lock_acquire();
#endif

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%1, %2		# atomic64_sub_return	\n"
		"	dsubu	%0, %1, %3				\n"
		"	scd	%0, %2					\n"
		"	beqzl	%0, 1b					\n"
		"	dsubu	%0, %1, %3				\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "=m" (v->counter)
		: "Ir" (i), "m" (v->counter)
		: "memory");
	} else if (kernel_uses_llsc && LOONGSON_LLSC_WAR) {
		long temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			__WEAK_LLSC_MB
			"	lld	%1, %2	# atomic64_sub_return	\n"
			"	dsubu	%0, %1, %3			\n"
			"	scd	%0, %2				\n"
			"	.set	mips0				\n"
			: "=&r" (result), "=&r" (temp), "=m" (v->counter)
			: "Ir" (i), "m" (v->counter)
			: "memory");
		} while (unlikely(!result));

		result = temp - i;
	} else if (kernel_uses_llsc) {
		long temp;

		do {
			__asm__ __volatile__(
			"	.set	mips3				\n"
			"	lld	%1, %2	# atomic64_sub_return	\n"
			"	dsubu	%0, %1, %3			\n"
			"	scd	%0, %2				\n"
			"	.set	mips0				\n"
			: "=&r" (result), "=&r" (temp), "=m" (v->counter)
			: "Ir" (i), "m" (v->counter)
			: "memory");
		} while (unlikely(!result));

		result = temp - i;
	} else {
#if 0
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result -= i;
		v->counter = result;
		raw_local_irq_restore(flags);
#endif
	}

	smp_llsc_mb();

#ifdef CONFIG_PHASE_LOCK
	loongson3_phase_lock_release(flags);
#endif

	return result;
}

/*
 * atomic64_sub_if_positive - conditionally subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic64_t
 *
 * Atomically test @v and subtract @i if @v is greater or equal than @i.
 * The function returns the old value of @v minus @i.
 */
static __inline__ long atomic64_sub_if_positive(long i, atomic64_t * v)
{
	long result;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%1, %2		# atomic64_sub_if_positive\n"
		"	dsubu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	scd	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqzl	%0, 1b					\n"
		"	 dsubu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "=m" (v->counter)
		: "Ir" (i), "m" (v->counter)
		: "memory");
	} else if (kernel_uses_llsc && LOONGSON_LLSC_WAR) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:				# atomic64_sub_if_positive\n"
		__WEAK_LLSC_MB
		"	lld	%1, %2					\n"
		"	dsubu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	scd	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqz	%0, 1b					\n"
		"	 dsubu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else if (kernel_uses_llsc) {
		long temp;

		__asm__ __volatile__(
		"	.set	mips3					\n"
		"1:	lld	%1, %2		# atomic64_sub_if_positive\n"
		"	dsubu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	scd	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqz	%0, 1b					\n"
		"	 dsubu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp), "+m" (v->counter)
		: "Ir" (i));
	} else {
#if 0
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result -= i;
		if (result >= 0)
			v->counter = result;
		raw_local_irq_restore(flags);
#endif
	}

	smp_llsc_mb();

	return result;
}

#define atomic64_cmpxchg(v, o, n) \
	((__typeof__((v)->counter))cmpxchg(&((v)->counter), (o), (n)))
#define atomic64_xchg(v, new) (xchg(&((v)->counter), (new)))

/**
 * atomic64_add_unless - add unless the number is a given value
 * @v: pointer of type atomic64_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns the old value of @v.
 */
static __inline__ int atomic64_add_unless(atomic64_t *v, long a, long u)
{
	long c, old;
	c = atomic64_read(v);
	for (;;) {
		if (unlikely(c == (u)))
			break;
		old = atomic64_cmpxchg((v), c, c + (a));
		if (likely(old == c))
			break;
		c = old;
	}
	return c != (u);
}

#define atomic64_inc_not_zero(v) atomic64_add_unless((v), 1, 0)

#define atomic64_dec_return(v) atomic64_sub_return(1, (v))
#define atomic64_inc_return(v) atomic64_add_return(1, (v))

/*
 * atomic64_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic64_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
#define atomic64_sub_and_test(i, v) (atomic64_sub_return((i), (v)) == 0)

/*
 * atomic64_inc_and_test - increment and test
 * @v: pointer of type atomic64_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
#define atomic64_inc_and_test(v) (atomic64_inc_return(v) == 0)

/*
 * atomic64_dec_and_test - decrement by 1 and test
 * @v: pointer of type atomic64_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
#define atomic64_dec_and_test(v) (atomic64_sub_return(1, (v)) == 0)

/*
 * atomic64_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer of type atomic64_t
 */
#define atomic64_dec_if_positive(v)	atomic64_sub_if_positive(1, v)

/*
 * atomic64_inc - increment atomic variable
 * @v: pointer of type atomic64_t
 *
 * Atomically increments @v by 1.
 */
#define atomic64_inc(v) atomic64_add(1, (v))

/*
 * atomic64_dec - decrement and test
 * @v: pointer of type atomic64_t
 *
 * Atomically decrements @v by 1.
 */
#define atomic64_dec(v) atomic64_sub(1, (v))

/*
 * atomic64_add_negative - add and test if negative
 * @v: pointer of type atomic64_t
 * @i: integer value to add
 *
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */
#define atomic64_add_negative(i, v) (atomic64_add_return(i, (v)) < 0)

#endif /* CONFIG_64BIT */

/*
 * atomic*_return operations are serializing but not the non-*_return
 * versions.
 */
#define smp_mb__before_atomic_dec()	smp_mb__before_llsc()
#define smp_mb__after_atomic_dec()	smp_llsc_mb()
#define smp_mb__before_atomic_inc()	smp_mb__before_llsc()
#define smp_mb__after_atomic_inc()	smp_llsc_mb()


#endif /* __CR_ATOMIC_H__ */
