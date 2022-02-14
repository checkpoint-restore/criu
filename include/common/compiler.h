#ifndef __CR_COMPILER_H__
#define __CR_COMPILER_H__

/*
 * Various definitions for success build,
 * picked from various places, mostly from
 * the linux kernel.
 */

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))
#define NELEMS_AS_ARRAY(x, y)	(sizeof(x) / sizeof((y)[0]))
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2 * !!(condition)]))

#define ASSIGN_TYPED(a, b)            \
	do {                          \
		(a) = (typeof(a))(b); \
	} while (0)
#define ASSIGN_MEMBER(a, b, m)                \
	do {                                  \
		ASSIGN_TYPED((a)->m, (b)->m); \
	} while (0)

#define __stringify_1(x...) #x
#define __stringify(x...)   __stringify_1(x)

#define NORETURN	__attribute__((__noreturn__))
#define __packed	__attribute__((__packed__))
#define __used		__attribute__((__used__))
#define __maybe_unused	__attribute__((unused))
#define __always_unused __attribute__((unused))
#define __must_check	__attribute__((__warn_unused_result__))

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

/* Not supported by clang */
#if __has_attribute(__externally_visible__)
#define __visible __attribute__((__externally_visible__))
#else
#define __visible
#endif

#define __section(S) __attribute__((__section__(#S)))

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#ifndef always_inline
#define always_inline __always_inline
#endif

#ifndef noinline
#define noinline __attribute__((noinline))
#endif

#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif

/*
 * Macro to define stack alignment.
 * aarch64 requires stack to be aligned to 16 bytes.
 */
#define __stack_aligned__ __attribute__((aligned(16)))

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

#define barrier() asm volatile("" ::: "memory")

#define container_of(ptr, type, member)                            \
	({                                                         \
		const typeof(((type *)0)->member) *__mptr = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); \
	})

#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF(t, f) (sizeof(((t *)0)->f))
#endif

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y)	   ((((x)-1) | __round_mask(x, y)) + 1)
#define round_down(x, y)   ((x) & ~__round_mask(x, y))
#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define ALIGN(x, a)	   (((x) + (a)-1) & ~((a)-1))

#define min(x, y)                              \
	({                                     \
		typeof(x) _min1 = (x);         \
		typeof(y) _min2 = (y);         \
		(void)(&_min1 == &_min2);      \
		_min1 < _min2 ? _min1 : _min2; \
	})

#define max(x, y)                              \
	({                                     \
		typeof(x) _max1 = (x);         \
		typeof(y) _max2 = (y);         \
		(void)(&_max1 == &_max2);      \
		_max1 > _max2 ? _max1 : _max2; \
	})

#define min_t(type, x, y)                          \
	({                                         \
		type __min1 = (x);                 \
		type __min2 = (y);                 \
		__min1 < __min2 ? __min1 : __min2; \
	})

#define max_t(type, x, y)                          \
	({                                         \
		type __max1 = (x);                 \
		type __max2 = (y);                 \
		__max1 > __max2 ? __max1 : __max2; \
	})

#define SWAP(x, y)                     \
	do {                           \
		typeof(x) ____val = x; \
		x = y;                 \
		y = ____val;           \
	} while (0)

#define is_log2(v) (((v) & ((v)-1)) == 0)

/*
 * Use "__ignore_value" to avoid a warning when using a function declared with
 * gcc's warn_unused_result attribute, but for which you really do want to
 * ignore the result.  Traditionally, people have used a "(void)" cast to
 * indicate that a function's return value is deliberately unused.  However,
 * if the function is declared with __attribute__((warn_unused_result)),
 * gcc issues a warning even with the cast.
 *
 * Caution: most of the time, you really should heed gcc's warning, and
 * check the return value.  However, in those exceptional cases in which
 * you're sure you know what you're doing, use this function.
 *
 * Normally casting an expression to void discards its value, but GCC
 * versions 3.4 and newer have __attribute__ ((__warn_unused_result__))
 * which may cause unwanted diagnostics in that case.  Use __typeof__
 * and __extension__ to work around the problem, if the workaround is
 * known to be needed.
 * Written by Jim Meyering, Eric Blake and Pádraig Brady.
 * (See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425 for the details)
 */
#if 3 < __GNUC__ + (4 <= __GNUC_MINOR__)
#define __ignore_value(x)                \
	({                               \
		__typeof__(x) __x = (x); \
		(void)__x;               \
	})
#else
#define __ignore_value(x) ((void)(x))
#endif

#endif /* __CR_COMPILER_H__ */
