#ifndef ATOMIC_H__
#define ATOMIC_H__

#define atomic_set(mem, v)					\
	({							\
		asm volatile ("lock xchg %0, %1\n"		\
				: "+r" (v), "+m" (*mem)		\
				:				\
				: "cc", "memory");		\
	})

#define atomic_get(mem)						\
	({							\
		uint32_t ret__ = 0;					\
		asm volatile ("lock xadd %0, %1\n"		\
				: "+r" (ret__),	"+m" (*mem)	\
				:				\
				: "cc", "memory");		\
		ret__;						\
	})

#define atomic_inc(mem)						\
	({							\
		uint32_t ret__ = 1;					\
		asm volatile ("lock xadd %0, %1\n"		\
				: "+r" (ret__),	"+m" (*mem)	\
				:				\
				: "cc", "memory");		\
		ret__;						\
	})

#define atomic_dec(mem)						\
	({							\
		uint32_t ret__ = -1;					\
		asm volatile ("lock xadd %0, %1\n"		\
				: "+r" (ret__),	"+m" (*mem)	\
				:				\
				: "cc", "memory");		\
		ret__;						\
	})

#endif /* ATOMIC_H__ */
