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

#endif /* ATOMIC_H__ */
