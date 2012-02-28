#ifndef CR_COMPILER_H_
#define CR_COMPILER_H_

/*
 * Various definitions for success build,
 * picked from various places, mostly from
 * the linux kernel.
 */

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))
#define BUILD_BUG_ON(condition)	((void)sizeof(char[1 - 2*!!(condition)]))

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

#define NORETURN 		__attribute__((__noreturn__))
#define __packed		__attribute__((__packed__))
#define __used			__attribute__((__used__))
#define __maybe_unused		__attribute__((unused))
#define __always_unused		__attribute__((unused))

#define __section(S)		__attribute__ ((__section__(#S)))

#ifndef __always_inline
# define __always_inline	inline __attribute__((always_inline))
#endif

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#ifndef always_inline
# define always_inline		__always_inline
#endif

#ifndef noinline
# define noinline		__attribute__((noinline))
#endif

#define __aligned(x)		__attribute__((aligned(x)))

#ifndef offsetof
# define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define barrier()		asm volatile("" ::: "memory")

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define __round_mask(x, y)	((__typeof__(x))((y) - 1))
#define round_up(x, y)		((((x) - 1) | __round_mask(x, y)) + 1)
#define round_down(x, y)	((x) & ~__round_mask(x, y))
#define DIV_ROUND_UP(n,d)	(((n) + (d) - 1) / (d))
#define ALIGN(x, a)		(((x) + (a) - 1) & ~((a) - 1))

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

#define is_log2(v)		(((v) & ((v) - 1)) == 0)

#endif /* CR_COMPILER_H_ */
