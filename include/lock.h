#ifndef CR_LOCK_H_
#define CR_LOCK_H_

#include <linux/futex.h>
#include <sys/time.h>
#include <limits.h>
#include <errno.h>

#include "types.h"
#include "atomic.h"
#include "syscall.h"
#include "util.h"

typedef struct {
	u32	raw;
} futex_t;

/* Get current futex @f value */
static inline u32 futex_get(futex_t *f)
{
	return atomic_get(&f->raw);
}

/* Set futex @f value to @v */
static inline void futex_set(futex_t *f, u32 v)
{
	atomic_set(&f->raw, v);
}

#define futex_init(f)	futex_set(f, 0)

/* Wait on futex @__f value @__v become in condition @__c */
#define futex_wait_if_cond(__f, __v, __cond)			\
	do {							\
		int ret;					\
		u32 tmp;					\
								\
		while (1) {					\
			tmp = (__f)->raw;			\
			if (tmp __cond (__v))			\
				break;				\
			ret = sys_futex(&(__f)->raw, FUTEX_WAIT,\
					tmp, NULL, NULL, 0);	\
			BUG_ON(ret < 0 && ret != -EWOULDBLOCK);	\
		}						\
	} while (0)

/* Set futex @f to @v and wake up all waiters */
static inline void futex_set_and_wake(futex_t *f, u32 v)
{
	atomic_set(&f->raw, v);
	BUG_ON(sys_futex(&f->raw, FUTEX_WAKE, INT_MAX, NULL, NULL, 0) < 0);
}

/* Decrement futex @f value and wake up all waiters */
static inline void futex_dec_and_wake(futex_t *f)
{
	atomic_dec(&f->raw);
	BUG_ON(sys_futex(&f->raw, FUTEX_WAKE, INT_MAX, NULL, NULL, 0) < 0);
}

/* Plain increment futex @f value */
static inline void futex_inc(futex_t *f) { f->raw++; }

/* Plain decrement futex @f value */
static inline void futex_dec(futex_t *f) { f->raw--; }

/* Wait until futex @f value become @v */
static inline void futex_wait_until(futex_t *f, u32 v)
{ futex_wait_if_cond(f, v, ==); }

/* Wait while futex @f value is greater than @v */
static inline void futex_wait_while_gt(futex_t *f, u32 v)
{ futex_wait_if_cond(f, v, <=); }

/* Wait while futex @f value is @v */
static inline void futex_wait_while(futex_t *f, u32 v)
{
	while (f->raw == v) {
		int ret = sys_futex(&f->raw, FUTEX_WAIT, v, NULL, NULL, 0);
		BUG_ON(ret < 0 && ret != -EWOULDBLOCK);
	}
}

/*
 * Init @mutex value
 */
static void always_inline cr_mutex_init(u32 *mutex)
{
	u32 c = 0;
	atomic_set(mutex, c);
}

/*
 * Lock @mutex
 */
static void always_inline cr_mutex_lock(u32 *mutex)
{
	u32 c;
	int ret;

	while ((c = atomic_inc(mutex))) {
		ret = sys_futex(mutex, FUTEX_WAIT, c + 1, NULL, NULL, 0);
		BUG_ON(ret < 0 && ret != -EWOULDBLOCK);
	}
}

/*
 * Unlock @mutex
 */
static void always_inline cr_mutex_unlock(u32 *mutex)
{
	u32 c = 0;
	int ret;

	atomic_set(mutex, c);

	ret = sys_futex(mutex, FUTEX_WAKE, 1, NULL, NULL, 0);
	BUG_ON(ret < 0);
}

#endif /* CR_LOCK_H_ */
