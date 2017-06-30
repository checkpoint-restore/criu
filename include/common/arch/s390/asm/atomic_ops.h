#ifndef __ARCH_S390_ATOMIC_OPS__
#define __ARCH_S390_ATOMIC_OPS__

#define __ATOMIC_OP(op_name, op_string)					\
static inline int op_name(int val, int *ptr)				\
{									\
	int old, new;							\
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

#define __ATOMIC_OPS(op_name, op_string)				\
	__ATOMIC_OP(op_name, op_string)					\
	__ATOMIC_OP(op_name##_barrier, op_string)

__ATOMIC_OPS(__atomic_add, "ar")
__ATOMIC_OPS(__atomic_and, "nr")
__ATOMIC_OPS(__atomic_or,  "or")
__ATOMIC_OPS(__atomic_xor, "xr")

#undef __ATOMIC_OPS

#define __ATOMIC64_OP(op_name, op_string)				\
static inline long op_name(long val, long *ptr)				\
{									\
	long old, new;							\
									\
	asm volatile(							\
		"0:	lgr	%[new],%[old]\n"			\
		op_string "	%[new],%[val]\n"			\
		"	csg	%[old],%[new],%[ptr]\n"			\
		"	jl	0b"					\
		: [old] "=d" (old), [new] "=&d" (new), [ptr] "+Q" (*ptr)\
		: [val] "d" (val), "0" (*ptr) : "cc", "memory");	\
	return old;							\
}

#define __ATOMIC64_OPS(op_name, op_string)				\
	__ATOMIC64_OP(op_name, op_string)				\
	__ATOMIC64_OP(op_name##_barrier, op_string)

__ATOMIC64_OPS(__atomic64_add, "agr")
__ATOMIC64_OPS(__atomic64_and, "ngr")
__ATOMIC64_OPS(__atomic64_or,  "ogr")
__ATOMIC64_OPS(__atomic64_xor, "xgr")

#undef __ATOMIC64_OPS

static inline int __atomic_cmpxchg(int *ptr, int old, int new)
{
	asm volatile(
		"	cs	%[old],%[new],%[ptr]"
		: [old] "+d" (old), [ptr] "+Q" (*ptr)
		: [new] "d" (new) : "cc", "memory");
	return old;
}

static inline long __atomic64_cmpxchg(long *ptr, long old, long new)
{
	asm volatile(
		"	csg	%[old],%[new],%[ptr]"
		: [old] "+d" (old), [ptr] "+Q" (*ptr)
		: [new] "d" (new) : "cc", "memory");
	return old;
}

#endif /* __ARCH_S390_ATOMIC_OPS__  */
