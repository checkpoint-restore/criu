#ifndef __UTILS_H__
#define __UTILS_H__


# define kernel_uses_llsc	1

typedef struct {
	int counter;
}atomic_t;


/*
 * FIXME: detect with compel_cpu_has_feature() if LL/SC implicitly
 * provide a memory barrier.
*/
#define __WEAK_LLSC_MB		"	sync	\n"

#define smp_llsc_mb()	__asm__ __volatile__(__WEAK_LLSC_MB : : :"memory")

#define smp_mb__before_llsc() smp_llsc_mb()
#define smp_mb__before_atomic()	smp_mb__before_llsc()
#define smp_mb__after_atomic()	smp_llsc_mb()

#endif /* __UTILS_H__ */
