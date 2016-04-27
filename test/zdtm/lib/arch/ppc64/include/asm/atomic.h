#ifndef __CR_ATOMIC_H__
#define __CR_ATOMIC_H__

/*
 * PowerPC atomic operations
 *
 * Copied from kernel header file arch/powerpc/include/asm/atomic.h
 */
typedef uint32_t atomic_t;

#define PPC_ATOMIC_ENTRY_BARRIER	"lwsync \n"
#define PPC_ATOMIC_EXIT_BARRIER		"sync  	\n"

#define ATOMIC_INIT(i)		{ (i) }

static __inline__ int atomic_get(const atomic_t *v)
{
	int t;

	__asm__ __volatile__("lwz%U1%X1 %0,%1" : "=r"(t) : "m"(*v));

	return t;
}

static __inline__ void atomic_set(atomic_t *v, int i)
{
	__asm__ __volatile__("stw%U0%X0 %1,%0" : "=m"(*v) : "r"(i));
}

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
	: "=&r" (t), "+m" (*v)					\
	: "r" (a), "r" (v)					\
	: "cc");							\
}									\

ATOMIC_OP(add, add)
ATOMIC_OP(sub, subf)

#undef ATOMIC_OP

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
	: "r" (v)
	: "cc", "xer", "memory");

	return t;
}

static __inline__ int atomic_inc(atomic_t *v)
{
	return atomic_inc_return(v) - 1;
}

static __inline__ void atomic_dec(atomic_t *v)
{
	int t;

	__asm__ __volatile__(
"1:	lwarx	%0,0,%2		# atomic_dec\n\
	addic	%0,%0,-1\n"
"	stwcx.	%0,0,%2\n\
	bne-	1b"
	: "=&r" (t), "+m" (*v)
	: "r" (v)
	: "cc", "xer");
}

#endif /* __CR_ATOMIC_H__ */
