#ifndef __CR_CMPXCHG_H__
#define __CR_CMPXCHG_H__

#define __cmpxchg_asm(ld, st, m, old, new)				\
({									\
	__typeof(*(m)) __ret;						\
									\
	if (kernel_uses_llsc) {						\
		__asm__ __volatile__(					\
		"	.set	push				\n"	\
		"	.set	noat				\n"	\
		"	.set	mips3				\n"	\
		"1:	" ld "	%0, %2		# __cmpxchg_asm \n"	\
		"	bne	%0, %z3, 2f			\n"	\
		"	.set	mips0				\n"	\
		"	move	$1, %z4				\n"	\
		"	.set	mips3				\n"	\
		"	" st "	$1, %1				\n"	\
		"	beqz	$1, 1b				\n"	\
		"	.set	pop				\n"	\
		"2:						\n"	\
		: "=&r" (__ret), "=R" (*m)				\
		: "R" (*m), "Jr" (old), "Jr" (new)			\
		: "memory");						\
	} else {                                                        \
	}								\
									\
	__ret;								\
})
/*
 * This function doesn't exist, so you'll get a linker error
 * if something tries to do an invalid cmpxchg().
 */
extern void __cmpxchg_called_with_bad_pointer(void);

#define __cmpxchg(ptr, old, new, pre_barrier, post_barrier)		\
({									\
	__typeof__(ptr) __ptr = (ptr);					\
	__typeof__(*(ptr)) __old = (old);				\
	__typeof__(*(ptr)) __new = (new);				\
	__typeof__(*(ptr)) __res = 0;					\
									\
	pre_barrier;							\
									\
	switch (sizeof(*(__ptr))) {					\
	case 4:								\
		__res = __cmpxchg_asm("ll", "sc", __ptr, __old, __new); \
		break;							\
	case 8:								\
		if (sizeof(long) == 8) {				\
			__res = __cmpxchg_asm("lld", "scd", __ptr,	\
					   __old, __new);		\
			break;						\
		}							\
	default:							\
		__cmpxchg_called_with_bad_pointer();			\
		break;							\
	}								\
									\
	post_barrier;							\
									\
	__res;								\
})

#define cmpxchg(ptr, old, new)		__cmpxchg(ptr, old, new, smp_mb__before_llsc(), smp_llsc_mb())

#endif /* __CR_CMPXCHG_H__ */
