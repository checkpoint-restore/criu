#ifndef ATOMIC_H__
#define ATOMIC_H__

#include "types.h"

typedef struct {
	u32 counter;
} atomic_t;

#define atomic_set(mem, v)					\
	({							\
		u32 ret__ = v;					\
		asm volatile ("lock xchg %0, %1\n"		\
				: "+r" (ret__), "+m" ((mem)->counter)	\
				:				\
				: "cc", "memory");		\
	})

#define atomic_get(mem)						\
	({							\
		u32 ret__ = 0;					\
		asm volatile ("lock xadd %0, %1\n"		\
				: "+r" (ret__),	"+m" ((mem)->counter)	\
				:				\
				: "cc", "memory");		\
		ret__;						\
	})

#define atomic_inc(mem)						\
	({							\
		u32 ret__ = 1;					\
		asm volatile ("lock xadd %0, %1\n"		\
				: "+r" (ret__),	"+m" ((mem)->counter)	\
				:				\
				: "cc", "memory");		\
		ret__;						\
	})

#define atomic_dec(mem)						\
	({							\
		u32 ret__ = -1;					\
		asm volatile ("lock xadd %0, %1\n"		\
				: "+r" (ret__),	"+m" ((mem)->counter)	\
				:				\
				: "cc", "memory");		\
		ret__;						\
	})

/* true if the result is 0, or false for all other cases. */
#define atomic_dec_and_test(mem)				\
	({							\
		unsigned char ret__;				\
		asm volatile ("lock decl %0; sete %1\n"		\
				: "+m" ((mem)->counter), "=qm" (ret__)	\
				:				\
				: "cc", "memory");		\
		ret__ != 0;					\
	})

#endif /* ATOMIC_H__ */
