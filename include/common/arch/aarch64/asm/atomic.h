#ifndef __CR_ATOMIC_H__
#define __CR_ATOMIC_H__

typedef struct {
	int counter;
} atomic_t;


/* Copied from the Linux header arch/arm/include/asm/barrier.h */

#define smp_mb()	asm volatile("dmb ish" : : : "memory")


/* Copied from the Linux kernel header arch/arm64/include/asm/atomic.h */

static inline int atomic_read(const atomic_t *v)
{
	return (*(volatile int *)&(v)->counter);
}

static inline void atomic_set(atomic_t *v, int i)
{
	v->counter = i;
}

#define atomic_get atomic_read


static inline int atomic_add_return(int i, atomic_t *v)
{
	unsigned long tmp;
	int result;

	asm volatile(
"1:	ldxr	%w0, %2\n"
"	add	%w0, %w0, %w3\n"
"	stlxr	%w1, %w0, %2\n"
"	cbnz	%w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
	: "Ir" (i)
	: "cc", "memory");

	smp_mb();
	return result;
}

static inline int atomic_sub_return(int i, atomic_t *v)
{
	unsigned long tmp;
	int result;

	asm volatile(
"1:	ldxr	%w0, %2\n"
"	sub	%w0, %w0, %w3\n"
"	stlxr	%w1, %w0, %2\n"
"	cbnz	%w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
	: "Ir" (i)
	: "cc", "memory");

	smp_mb();
	return result;
}

static inline int atomic_inc(atomic_t *v) { return atomic_add_return(1, v) - 1; }

static inline int atomic_add(int val, atomic_t *v) { return atomic_add_return(val, v) - val; }

static inline int atomic_dec(atomic_t *v) { return atomic_sub_return(1, v) + 1; }

/* true if the result is 0, or false for all other cases. */
#define atomic_dec_and_test(v) (atomic_sub_return(1, v) == 0)
#define atomic_dec_return(v)  (atomic_sub_return(1, v))

#define atomic_inc_return(v)	(atomic_add_return(1, v))

static inline int atomic_cmpxchg(atomic_t *ptr, int old, int new)
{
	unsigned long tmp;
	int oldval;

	smp_mb();

	asm volatile("// atomic_cmpxchg\n"
"1:	ldxr	%w1, %2\n"
"	cmp	%w1, %w3\n"
"	b.ne	2f\n"
"	stxr	%w0, %w4, %2\n"
"	cbnz	%w0, 1b\n"
"2:"
	: "=&r" (tmp), "=&r" (oldval), "+Q" (ptr->counter)
	: "Ir" (old), "r" (new)
	: "cc");

	smp_mb();
	return oldval;
}

#endif /* __CR_ATOMIC_H__ */
