#ifndef __CR_ATOMIC_H__
#define __CR_ATOMIC_H__

//#include <linux/types.h>
//#include "common/compiler.h"
//#include "common/arch/mips/asm/utils.h"
//#include "common/arch/mips/asm/cmpxchg.h"

typedef uint32_t atomic_t;
/* typedef struct { */
/* 	int counter; */
/* }atomic_t; */

#define __WEAK_LLSC_MB		"	sync	\n"

#define smp_llsc_mb()	__asm__ __volatile__(__WEAK_LLSC_MB : : :"memory")

#define smp_mb__before_llsc() smp_llsc_mb()
#define smp_mb__before_atomic()	smp_mb__before_llsc()
#define smp_mb__after_atomic()	smp_llsc_mb()

#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)

#define atomic_get(v)		(*(volatile int *)v)
#define atomic_set(v, i)		((*v) = (i))

//#define atomic_get atomic_read

/*
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */

static __inline__ void atomic_add(int i, atomic_t * v)
{
    int temp;

    do {
	__asm__ __volatile__(
			     "	.set	mips3				\n"
			     "	ll	%0, %1		# atomic_add	\n"
			     "	addu	%0, %2				\n"
			     "	sc	%0, %1				\n"
			     "	.set	mips0				\n"
			     : "=&r" (temp), "+m" (*v)
			     : "Ir" (i));
    } while (unlikely(!temp));
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
    int temp;

    do {
	__asm__ __volatile__(
			     "	.set	mips3				\n"
			     "	ll	%0, %1		# atomic_sub	\n"
			     "	subu	%0, %2				\n"
			     "	sc	%0, %1				\n"
			     "	.set	mips0				\n"
			     : "=&r" (temp), "+m" (*v)
			     : "Ir" (i));
    } while (unlikely(!temp));
}

/*
 * Same as above, but return the result value
 */
static __inline__ int atomic_add_return(int i, atomic_t * v)
{
	int result;
	int temp;

	smp_mb__before_llsc();

	do {
	    __asm__ __volatile__(
				 "	.set	mips3				\n"
				 "	ll	%1, %2	# atomic_add_return	\n"
				 "	addu	%0, %1, %3			\n"
				 "	sc	%0, %2				\n"
				 "	.set	mips0				\n"
				 : "=&r" (result), "=&r" (temp), "+m" (*v)
				 : "Ir" (i));
	} while (unlikely(!result));

	result = temp + i;

	smp_llsc_mb();

	return result;
}

static __inline__ int atomic_sub_return(int i, atomic_t * v)
{
	int result;
	int temp;

	smp_mb__before_llsc();

	do {
	    __asm__ __volatile__(
				 "	.set	mips3				\n"
				 "	ll	%1, %2	# atomic_sub_return	\n"
				 "	subu	%0, %1, %3			\n"
				 "	sc	%0, %2				\n"
				 "	.set	mips0				\n"
				 : "=&r" (result), "=&r" (temp), "+m" (*v)
				 : "Ir" (i));
	} while (unlikely(!result));

	result = temp - i;

	smp_llsc_mb();

	return result;
}

#define atomic_cmpxchg(v, o, n) (cmpxchg(&((v)->counter), (o), (n)))
#define atomic_dec_return(v) atomic_sub_return(1, (v))
#define atomic_inc_return(v) atomic_add_return(1, (v))

static inline unsigned int atomic_inc(atomic_t *v) { return atomic_add_return(1, v) - 1; }
static inline unsigned int atomic_dec(atomic_t *v) { return atomic_sub_return(1, v) + 1; }
#endif /* __CR_ATOMIC_H__ */
