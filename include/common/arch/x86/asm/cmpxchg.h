#ifndef __CR_CMPXCHG_H__
#define __CR_CMPXCHG_H__

#include <stdint.h>

#define LOCK_PREFIX "\n\tlock; "

#define __X86_CASE_B 1
#define __X86_CASE_W 2
#define __X86_CASE_L 4
#define __X86_CASE_Q 8

/*
 * An exchange-type operation, which takes a value and a pointer, and
 * returns the old value. Make sure you never reach non-case statement
 * here, otherwise behaviour is undefined.
 */
#define __xchg_op(ptr, arg, op, lock)                                                                        \
	({                                                                                                   \
		__typeof__(*(ptr)) __ret = (arg);                                                            \
		switch (sizeof(*(ptr))) {                                                                    \
		case __X86_CASE_B:                                                                           \
			asm volatile(lock #op "b %b0, %1\n" : "+q"(__ret), "+m"(*(ptr)) : : "memory", "cc"); \
			break;                                                                               \
		case __X86_CASE_W:                                                                           \
			asm volatile(lock #op "w %w0, %1\n" : "+r"(__ret), "+m"(*(ptr)) : : "memory", "cc"); \
			break;                                                                               \
		case __X86_CASE_L:                                                                           \
			asm volatile(lock #op "l %0, %1\n" : "+r"(__ret), "+m"(*(ptr)) : : "memory", "cc");  \
			break;                                                                               \
		case __X86_CASE_Q:                                                                           \
			asm volatile(lock #op "q %q0, %1\n" : "+r"(__ret), "+m"(*(ptr)) : : "memory", "cc"); \
			break;                                                                               \
		}                                                                                            \
		__ret;                                                                                       \
	})

#define __xadd(ptr, inc, lock) __xchg_op((ptr), (inc), xadd, lock)
#define xadd(ptr, inc)	       __xadd((ptr), (inc), "lock ;")

/* Borrowed from linux kernel arch/x86/include/asm/cmpxchg.h */

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */
#define __raw_cmpxchg(ptr, old, new, size, lock)                               \
	({                                                                     \
		__typeof__(*(ptr)) __ret;                                      \
		__typeof__(*(ptr)) __old = (old);                              \
		__typeof__(*(ptr)) __new = (new);                              \
		switch (size) {                                                \
		case __X86_CASE_B: {                                           \
			volatile uint8_t *__ptr = (volatile uint8_t *)(ptr);   \
			asm volatile(lock "cmpxchgb %2,%1"                     \
				     : "=a"(__ret), "+m"(*__ptr)               \
				     : "q"(__new), "0"(__old)                  \
				     : "memory");                              \
			break;                                                 \
		}                                                              \
		case __X86_CASE_W: {                                           \
			volatile uint16_t *__ptr = (volatile uint16_t *)(ptr); \
			asm volatile(lock "cmpxchgw %2,%1"                     \
				     : "=a"(__ret), "+m"(*__ptr)               \
				     : "r"(__new), "0"(__old)                  \
				     : "memory");                              \
			break;                                                 \
		}                                                              \
		case __X86_CASE_L: {                                           \
			volatile uint32_t *__ptr = (volatile uint32_t *)(ptr); \
			asm volatile(lock "cmpxchgl %2,%1"                     \
				     : "=a"(__ret), "+m"(*__ptr)               \
				     : "r"(__new), "0"(__old)                  \
				     : "memory");                              \
			break;                                                 \
		}                                                              \
		case __X86_CASE_Q: {                                           \
			volatile uint64_t *__ptr = (volatile uint64_t *)(ptr); \
			asm volatile(lock "cmpxchgq %2,%1"                     \
				     : "=a"(__ret), "+m"(*__ptr)               \
				     : "r"(__new), "0"(__old)                  \
				     : "memory");                              \
			break;                                                 \
		}                                                              \
		}                                                              \
		__ret;                                                         \
	})

#define __cmpxchg(ptr, old, new, size) __raw_cmpxchg((ptr), (old), (new), (size), LOCK_PREFIX)
#define cmpxchg(ptr, old, new)	       __cmpxchg(ptr, old, new, sizeof(*(ptr)))

#endif /* __CR_CMPXCHG_H__ */
