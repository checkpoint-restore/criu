#ifndef __ARCH_S390_ATOMIC__
#define __ARCH_S390_ATOMIC__

#include <stdint.h>

typedef uint32_t atomic_t;

#define __ATOMIC_OP(op_name, op_type, op_string)			\
static inline op_type op_name(op_type val, op_type *ptr)		\
{									\
	op_type old, new;						\
									\
	asm volatile(							\
		"0:	lr	%[new],%[old]\n"			\
		op_string "	%[new],%[val]\n"			\
		"	cs	%[old],%[new],%[ptr]\n"			\
		"	jl	0b"					\
		: [old] "=d" (old), [new] "=&d" (new), [ptr] "+Q" (*ptr)\
		: [val] "d" (val), "0" (*ptr) : "cc", "memory");	\
	return old;							\
}

#define __ATOMIC_OPS(op_name, op_type, op_string)			\
	__ATOMIC_OP(op_name, op_type, op_string)			\
	__ATOMIC_OP(op_name##_barrier, op_type, op_string)

__ATOMIC_OPS(__atomic_add, uint32_t, "ar")

#undef __ATOMIC_OPS
#undef __ATOMIC_OP

static inline int atomic_get(const atomic_t *v)
{
	int c;

	asm volatile(
		"	l	%0,%1\n"
		: "=d" (c) : "Q" (*v));
	return c;
}

static inline void atomic_set(atomic_t *v, int i)
{
	asm volatile(
		"	st	%1,%0\n"
		: "=Q" (*v) : "d" (i));
}

static inline int atomic_add_return(int i, atomic_t *v)
{
	return __atomic_add_barrier(i, v) + i;
}

static inline void atomic_add(int i, atomic_t *v)
{
	__atomic_add(i, v);
}

#define atomic_sub(_i, _v)		atomic_add(-(int)(_i), _v)

static inline int atomic_inc(atomic_t *v)
{
	return atomic_add_return(1, v) - 1;
}

#define atomic_dec(_v)			atomic_sub(1, _v)

#endif /* __ARCH_S390_ATOMIC__  */
