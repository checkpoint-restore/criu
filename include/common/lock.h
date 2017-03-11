#ifndef __CR_COMMON_LOCK_H__
#define __CR_COMMON_LOCK_H__

#include <stdint.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <limits.h>
#include <errno.h>
#include "common/asm/atomic.h"
#include "common/compiler.h"

#define LOCK_BUG_ON(condition)							\
	if ((condition))							\
		*(volatile unsigned long *)NULL = 0xdead0000 + __LINE__
#define LOCK_BUG()	LOCK_BUG_ON(1)

#ifdef CR_NOGLIBC
# include <compel/plugins/std/syscall.h>
#else
# include <unistd.h>
# include <sys/syscall.h>
static inline long sys_futex (uint32_t *addr1, int op, uint32_t val1,
			      struct timespec *timeout, uint32_t *addr2, uint32_t val3)
{
       int rc = syscall(SYS_futex, addr1, op, val1, timeout, addr2, val3);
       if (rc == -1) rc = -errno;
       return rc;
}
#endif

typedef struct {
	atomic_t raw;
} __aligned(sizeof(int)) futex_t;

#define FUTEX_ABORT_FLAG	(0x80000000)
#define FUTEX_ABORT_RAW		(-1U)

/* Get current futex @f value */
static inline uint32_t futex_get(futex_t *f)
{
	return atomic_read(&f->raw);
}

/* Set futex @f value to @v */
static inline void futex_set(futex_t *f, uint32_t v)
{
	atomic_set(&f->raw, (int)v);
}

#define futex_init(f)	futex_set(f, 0)

/* Wait on futex @__f value @__v become in condition @__c */
#define futex_wait_if_cond(__f, __v, __cond)			\
	do {							\
		int ret;					\
		uint32_t tmp;					\
								\
		while (1) {					\
			struct timespec to = {.tv_sec = 120};	\
			tmp = futex_get(__f);			\
			if ((tmp & FUTEX_ABORT_FLAG) ||		\
			    (tmp __cond (__v)))			\
				break;				\
			ret = sys_futex((uint32_t *)&(__f)->raw.counter, FUTEX_WAIT,\
					tmp, &to, NULL, 0);	\
			if (ret == -ETIMEDOUT)			\
				continue;			\
			if (ret == -EINTR || ret == -EWOULDBLOCK) \
				continue;			\
			if (ret < 0)				\
				LOCK_BUG();			\
		}						\
	} while (0)

/* Set futex @f to @v and wake up all waiters */
static inline void futex_set_and_wake(futex_t *f, uint32_t v)
{
	atomic_set(&f->raw, (int)v);
	LOCK_BUG_ON(sys_futex((uint32_t *)&f->raw.counter, FUTEX_WAKE, INT_MAX, NULL, NULL, 0) < 0);
}

/* Wake up all futex @f waiters */
static inline void futex_wake(futex_t *f)
{
	LOCK_BUG_ON(sys_futex((uint32_t *)&f->raw.counter, FUTEX_WAKE, INT_MAX, NULL, NULL, 0) < 0);
}

/* Mark futex @f as wait abort needed and wake up all waiters */
static inline void futex_abort_and_wake(futex_t *f)
{
	BUILD_BUG_ON(!(FUTEX_ABORT_RAW & FUTEX_ABORT_FLAG));
	futex_set_and_wake(f, FUTEX_ABORT_RAW);
}

/* Decrement futex @f value and wake up all waiters */
static inline void futex_dec_and_wake(futex_t *f)
{
	atomic_dec(&f->raw);
	LOCK_BUG_ON(sys_futex((uint32_t *)&f->raw.counter, FUTEX_WAKE, INT_MAX, NULL, NULL, 0) < 0);
}

/* Increment futex @f value and wake up all waiters */
static inline void futex_inc_and_wake(futex_t *f)
{
	atomic_inc(&f->raw);
	LOCK_BUG_ON(sys_futex((uint32_t *)&f->raw.counter, FUTEX_WAKE, INT_MAX, NULL, NULL, 0) < 0);
}

/* Plain increment futex @f value */
static inline void futex_inc(futex_t *f) { atomic_inc(&f->raw); }

/* Plain decrement futex @f value */
static inline void futex_dec(futex_t *f) { atomic_dec(&f->raw); }

/* Wait until futex @f value become @v */
#define futex_wait_until(f, v) futex_wait_if_cond(f, v, ==)

/* Wait while futex @f value is greater than @v */
#define futex_wait_while_gt(f, v) futex_wait_if_cond(f, v, <=)

/* Wait while futex @f value is less than @v */
#define futex_wait_while_lt(f, v) futex_wait_if_cond(f, v, >=)

/* Wait while futex @f value is equal to @v */
#define futex_wait_while_eq(f, v) futex_wait_if_cond(f, v, !=)

/* Wait while futex @f value is @v */
static inline void futex_wait_while(futex_t *f, uint32_t v)
{
	while ((uint32_t)atomic_read(&f->raw) == v) {
		int ret = sys_futex((uint32_t *)&f->raw.counter, FUTEX_WAIT, v, NULL, NULL, 0);
		LOCK_BUG_ON(ret < 0 && ret != -EWOULDBLOCK);
	}
}

typedef struct {
	atomic_t	raw;
} mutex_t;

static inline void mutex_init(mutex_t *m)
{
	uint32_t c = 0;
	atomic_set(&m->raw, (int)c);
}

static inline void mutex_lock(mutex_t *m)
{
	uint32_t c;
	int ret;

	while ((c = (uint32_t)atomic_inc_return(&m->raw)) != 1) {
		ret = sys_futex((uint32_t *)&m->raw.counter, FUTEX_WAIT, c, NULL, NULL, 0);
		LOCK_BUG_ON(ret < 0 && ret != -EWOULDBLOCK);
	}
}

static inline void mutex_unlock(mutex_t *m)
{
	uint32_t c = 0;
	atomic_set(&m->raw, (int)c);
	LOCK_BUG_ON(sys_futex((uint32_t *)&m->raw.counter, FUTEX_WAKE, 1, NULL, NULL, 0) < 0);
}

#endif /* __CR_COMMON_LOCK_H__ */
