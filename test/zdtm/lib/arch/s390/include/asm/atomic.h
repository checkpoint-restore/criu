#ifndef __ARCH_S390_ATOMIC__
#define __ARCH_S390_ATOMIC__

#include <stdint.h>

typedef uint32_t atomic_t;

#define __ATOMIC_OP(op_name, op_type, op_string, op_barrier)		\
static inline op_type op_name(op_type val, op_type *ptr)		\
{									\
	op_type old;							\
									\
	asm volatile(							\
		op_string "	%[old],%[val],%[ptr]\n"			\
		op_barrier						\
		: [old] "=d" (old), [ptr] "+Q" (*ptr)			\
		: [val] "d" (val) : "cc", "memory");			\
	return old;							\
}									\

#define __ATOMIC_OPS(op_name, op_type, op_string)			\
	__ATOMIC_OP(op_name, op_type, op_string, "\n")			\
	__ATOMIC_OP(op_name##_barrier, op_type, op_string, "bcr 14,0\n")

__ATOMIC_OPS(__atomic_add, uint32_t, "laa")

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
