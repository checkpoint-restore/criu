#ifndef __ARCH_S390_ATOMIC__
#define __ARCH_S390_ATOMIC__

#include "common/arch/s390/asm/atomic_ops.h"
#include "common/compiler.h"

#define ATOMIC_INIT(i) \
	{              \
		(i)    \
	}

typedef struct {
	int counter;
} atomic_t;

static inline int atomic_read(const atomic_t *v)
{
	int c;

	asm volatile("	l	%0,%1\n" : "=d"(c) : "Q"(v->counter));
	return c;
}

static inline void atomic_set(atomic_t *v, int i)
{
	asm volatile("	st	%1,%0\n" : "=Q"(v->counter) : "d"(i));
}

static inline int atomic_add_return(int i, atomic_t *v)
{
	return __atomic_add_barrier(i, &v->counter) + i;
}

static inline void atomic_add(int i, atomic_t *v)
{
	__atomic_add(i, &v->counter);
}

#define atomic_inc(_v)		  atomic_add(1, _v)
#define atomic_inc_return(_v)	  atomic_add_return(1, _v)
#define atomic_sub(_i, _v)	  atomic_add(-(int)(_i), _v)
#define atomic_sub_return(_i, _v) atomic_add_return(-(int)(_i), _v)
#define atomic_dec(_v)		  atomic_sub(1, _v)
#define atomic_dec_return(_v)	  atomic_sub_return(1, _v)
#define atomic_dec_and_test(_v)	  (atomic_sub_return(1, _v) == 0)

#define ATOMIC_OPS(op)                                     \
	static inline void atomic_##op(int i, atomic_t *v) \
	{                                                  \
		__atomic_##op(i, &v->counter);             \
	}

ATOMIC_OPS(and)
ATOMIC_OPS(or)
ATOMIC_OPS(xor)

#undef ATOMIC_OPS

static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return __atomic_cmpxchg(&v->counter, old, new);
}

#endif /* __ARCH_S390_ATOMIC__  */
