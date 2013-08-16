#ifndef __CR_ATOMIC_H__
#define __CR_ATOMIC_H__

typedef struct {
	int counter;
} atomic_t;


/* Copied from the Linux kernel header arch/arm/include/asm/atomic.h */

#if defined(CONFIG_ARMV7)

#define smp_mb() __asm__ __volatile__ ("dmb" : : : "memory")

#elif defined(CONFIG_ARMV6)

#define smp_mb() __asm__ __volatile__ ("mcr p15, 0, %0, c7, c10, 5"	: : "r" (0) : "memory")

#endif

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

	smp_mb();

	__asm__ __volatile__("@ atomic_add_return\n"
"1:	ldrex	%0, [%3]\n"
"	add	%0, %0, %4\n"
"	strex	%1, %0, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b\n"
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
        : "r" (&v->counter), "Ir" (i)
	: "cc");

	smp_mb();

	return result;
}

static inline int atomic_sub_return(int i, atomic_t *v)
{
	unsigned long tmp;
	int result;

	smp_mb();

	__asm__ __volatile__("@ atomic_sub_return\n"
"1:	ldrex	%0, [%3]\n"
"	sub	%0, %0, %4\n"
"	strex	%1, %0, [%3]\n"
"	teq	%1, #0\n"
"	bne	1b\n"
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)
	: "r" (&v->counter), "Ir" (i)
	: "cc");

	smp_mb();

	return result;
}

static inline int atomic_inc(atomic_t *v) { return atomic_add_return(1, v) - 1; }

static inline int atomic_add(int val, atomic_t *v) { return atomic_add_return(val, v) - val; }

static inline int atomic_dec(atomic_t *v) { return atomic_sub_return(1, v) + 1; }

/* true if the result is 0, or false for all other cases. */
#define atomic_dec_and_test(v) (atomic_sub_return(1, v) == 0)

#define atomic_inc_return(v)	(atomic_add_return(1, v))

#endif /* __CR_ATOMIC_H__ */
