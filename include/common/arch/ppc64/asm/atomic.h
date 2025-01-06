#ifndef __CR_ATOMIC_H__
#define __CR_ATOMIC_H__

/*
 * PowerPC atomic operations
 *
 * Copied from kernel header file arch/powerpc/include/asm/atomic.h
 */

typedef struct {
	int counter;
} atomic_t;

#include "common/arch/ppc64/asm/cmpxchg.h"

#define PPC_ATOMIC_ENTRY_BARRIER "lwsync \n"
#define PPC_ATOMIC_EXIT_BARRIER	 "sync  	\n"

#define ATOMIC_INIT(i) \
	{              \
		(i)    \
	}

static __inline__ int atomic_read(const atomic_t *v)
{
	int t;

	__asm__ __volatile__("lwz%U1%X1 %0,%1" : "=r"(t) : "m"(v->counter));

	return t;
}

static __inline__ void atomic_set(atomic_t *v, int i)
{
	__asm__ __volatile__("stw%U0%X0 %1,%0" : "=m"(v->counter) : "r"(i));
}

/* clang-format off */
#define ATOMIC_OP(op, asm_op)						\
static __inline__ void atomic_##op(int a, atomic_t *v)			\
{									\
	int t;								\
									\
	__asm__ __volatile__(						\
"1:	lwarx	%0,0,%3		# atomic_" #op "\n"			\
	#asm_op " %0,%2,%0\n"						\
"	stwcx.	%0,0,%3 \n"						\
"	bne-	1b\n"							\
	: "=&r" (t), "+m" (v->counter)					\
	: "r" (a), "r" (&v->counter)					\
	: "cc");							\
}									\

ATOMIC_OP(add, add)
ATOMIC_OP(sub, subf)

#undef ATOMIC_OP

static __inline__ void atomic_inc(atomic_t *v)
{
	int t;

	__asm__ __volatile__(
"1:	lwarx	%0,0,%2		# atomic_inc\n\
	addic	%0,%0,1\n"
"	stwcx.	%0,0,%2 \n\
	bne-	1b"
	: "=&r" (t), "+m" (v->counter)
	: "r" (&v->counter)
	: "cc", "xer");
}

static __inline__ int atomic_inc_return(atomic_t *v)
{
	int t;

	__asm__ __volatile__(
	PPC_ATOMIC_ENTRY_BARRIER \
"1:	lwarx	%0,0,%1		# atomic_inc_return\n\
	addic	%0,%0,1\n"
"	stwcx.	%0,0,%1 \n\
	bne-	1b \n" \
	PPC_ATOMIC_EXIT_BARRIER
	: "=&r" (t)
	: "r" (&v->counter)
	: "cc", "xer", "memory");

	return t;
}

/*
 * atomic_inc_and_test - increment and test
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */

static __inline__ void atomic_dec(atomic_t *v)
{
	int t;

	__asm__ __volatile__(
"1:	lwarx	%0,0,%2		# atomic_dec\n\
	addic	%0,%0,-1\n"
"	stwcx.	%0,0,%2\n\
	bne-	1b"
	: "=&r" (t), "+m" (v->counter)
	: "r" (&v->counter)
	: "cc", "xer");
}

static __inline__ int atomic_sub_return(int a, atomic_t *v)
{
	int t;

	__asm__ __volatile__(
"	\nLWSYNC\n"
"1:	lwarx	%0,0,%2		# atomic_sub_return\n\
	subf	%0,%1,%0\n"
"	stwcx.	%0,0,%2 \n\
	bne-	1b"
"	\nsync\n"
	: "=&r" (t)
	: "r" (a), "r" (&v->counter)
	: "cc", "memory");

	return t;
}
/* clang-format on */

/* true if the result is 0, or false for all other cases. */
#define atomic_dec_and_test(v) (atomic_sub_return(1, v) == 0)
#define atomic_dec_return(v)   (atomic_sub_return(1, v))

#define atomic_cmpxchg(v, o, n) (cmpxchg(&((v)->counter), (o), (n)))

#endif /* __CR_ATOMIC_H__ */
