#ifndef __CR_CMPXCHG_H__
#define __CR_CMPXCHG_H__

/*
 * Copied from kernel header file arch/powerpc/include/asm/cmpxchg.h
 */

#define PPC_ACQUIRE_BARRIER		"isync	\n"
#define PPC_RELEASE_BARRIER		"lwsync	\n"

/*
 * Compare and exchange - if *p == old, set it to new,
 * and return the old value of *p.
 */

static __always_inline unsigned long
__cmpxchg_u32(volatile unsigned int *p, unsigned long old, unsigned long new)
{
	unsigned int prev;

	__asm__ __volatile__ (
	PPC_RELEASE_BARRIER \
"1:	lwarx	%0,0,%2		# __cmpxchg_u32\n\
	cmpw	0,%0,%3\n\
	bne-	2f\n"
"	stwcx.	%4,0,%2\n\
	bne-	1b \n" \
	PPC_ACQUIRE_BARRIER
	"\n\
2:"
	: "=&r" (prev), "+m" (*p)
	: "r" (p), "r" (old), "r" (new)
	: "cc", "memory");

	return prev;
}

static __always_inline unsigned long
__cmpxchg_u64(volatile unsigned long *p, unsigned long old, unsigned long new)
{
	unsigned long prev;

	__asm__ __volatile__ (
	PPC_RELEASE_BARRIER \
"1:	ldarx	%0,0,%2		# __cmpxchg_u64\n\
	cmpd	0,%0,%3\n\
	bne-	2f\n\
	stdcx.	%4,0,%2\n\
	bne-	1b \n" \
	PPC_ACQUIRE_BARRIER
	"\n\
2:"
	: "=&r" (prev), "+m" (*p)
	: "r" (p), "r" (old), "r" (new)
	: "cc", "memory");

	return prev;
}

/* This function doesn't exist, so you'll get a linker error
   if something tries to do an invalid cmpxchg().  */
#ifdef CR_DEBUG
static inline void __cmpxchg_called_with_bad_pointer(void)
{
	__asm__ __volatile__ (
		"1:	twi 	31,0,0	# trap\n"
		"	b 	1b"
		: : : "memory");
}
#else
extern void __cmpxchg_called_with_bad_pointer(void);
#endif

static __always_inline unsigned long
__cmpxchg(volatile void *ptr, unsigned long old, unsigned long new,
	  unsigned int size)
{
	switch (size) {
	case 4:
		return __cmpxchg_u32(ptr, old, new);
	case 8:
		return __cmpxchg_u64(ptr, old, new);
	}
	__cmpxchg_called_with_bad_pointer();
	return old;
}

#define cmpxchg(ptr, o, n)						 \
  ({									 \
     __typeof__(*(ptr)) _o_ = (o);					 \
     __typeof__(*(ptr)) _n_ = (n);					 \
     (__typeof__(*(ptr))) __cmpxchg((ptr), (unsigned long)_o_,		 \
				    (unsigned long)_n_, sizeof(*(ptr))); \
  })

#endif /* __CR_CMPXCHG_H__ */
