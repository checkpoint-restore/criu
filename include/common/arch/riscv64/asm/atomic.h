#ifndef __CR_ATOMIC_H__
#define __CR_ATOMIC_H__

typedef struct {
	int counter;
} atomic_t;

/* Copied from the Linux header arch/riscv/include/asm/barrier.h */

#define nop() __asm__ __volatile__("nop")

#define RISCV_FENCE(p, s) __asm__ __volatile__("fence " #p "," #s : : : "memory")

/* These barriers need to enforce ordering on both devices or memory. */
#define mb()  RISCV_FENCE(iorw, iorw)
#define rmb() RISCV_FENCE(ir, ir)
#define wmb() RISCV_FENCE(ow, ow)

/* These barriers do not need to enforce ordering on devices, just memory. */
#define __smp_mb()  RISCV_FENCE(rw, rw)
#define __smp_rmb() RISCV_FENCE(r, r)
#define __smp_wmb() RISCV_FENCE(w, w)

#define __smp_store_release(p, v)                   \
	do {                                        \
		compiletime_assert_atomic_type(*p); \
		RISCV_FENCE(rw, w);                 \
		WRITE_ONCE(*p, v);                  \
	} while (0)

#define __smp_load_acquire(p)                       \
	({                                          \
		typeof(*p) ___p1 = READ_ONCE(*p);   \
		compiletime_assert_atomic_type(*p); \
		RISCV_FENCE(r, rw);                 \
		___p1;                              \
	})

/* Copied from the Linux kernel header arch/riscv/include/asm/atomic.h */

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
	int result;

	asm volatile("amoadd.w.aqrl %1, %2, %0" : "+A"(v->counter), "=r"(result) : "r"(i) : "memory");
	__smp_mb();
	return result + i;
}

static inline int atomic_sub_return(int i, atomic_t *v)
{
	return atomic_add_return(-i, v);
}

static inline int atomic_inc(atomic_t *v)
{
	return atomic_add_return(1, v) - 1;
}

static inline int atomic_add(int val, atomic_t *v)
{
	return atomic_add_return(val, v) - val;
}

static inline int atomic_dec(atomic_t *v)
{
	return atomic_sub_return(1, v) + 1;
}

/* true if the result is 0, or false for all other cases. */
#define atomic_dec_and_test(v) (atomic_sub_return(1, v) == 0)
#define atomic_dec_return(v)   (atomic_sub_return(1, v))

#define atomic_inc_return(v) (atomic_add_return(1, v))

static inline int atomic_cmpxchg(atomic_t *ptr, int old, int new)
{
	unsigned long tmp;
	int oldval;

	__smp_mb();

	asm volatile("1:\n"
		     "  lr.w %1, %2\n"
		     "  bne %1, %3, 2f\n"
		     "  sc.w %0, %4, %2\n"
		     "  bnez %0, 1b\n"
		     "2:"
		     : "=&r"(tmp), "=&r"(oldval), "+A"(ptr->counter)
		     : "r"(old), "r"(new)
		     : "memory");

	__smp_mb();
	return oldval;
}

#endif /* __CR_ATOMIC_H__ */
