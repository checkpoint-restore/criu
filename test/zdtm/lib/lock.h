#ifndef CR_LOCK_H_
#define CR_LOCK_H_

#include <linux/futex.h>
#include <linux/unistd.h>
#include <sys/time.h>
#include <limits.h>
#include <errno.h>
#include <atomic.h>

#define BUG_ON(condition)						\
	do {								\
		if ((condition)) {					\
			raise(SIGABRT);					\
			*(volatile unsigned long *)NULL = 0xdead0000 + __LINE__; \
		}							\
	} while (0)
typedef struct {
	uint32_t	raw;
} futex_t;

#define FUTEX_ABORT_FLAG	(0x80000000)
#define FUTEX_ABORT_RAW		(-1U)

static inline int sys_futex(unsigned int *uaddr, int op, unsigned int val, const struct timespec *timeout,
                 int *uaddr2, unsigned int val3)
{
	return syscall(__NR_futex, uaddr, op, val, timeout, uaddr2, val3);
}

/* Get current futex @f value */
static inline uint32_t futex_get(futex_t *f)
{
	return atomic_get(&f->raw);
}

/* Set futex @f value to @v */
static inline void futex_set(futex_t *f, uint32_t v)
{
	atomic_set(&f->raw, v);
}

#define futex_init(f)	futex_set(f, 0)

/* Wait on futex @__f value @__v become in condition @__c */
#define futex_wait_if_cond(__f, __v, __cond)			\
	do {							\
		int ret;					\
		uint32_t tmp;					\
								\
		while (1) {					\
			tmp = (__f)->raw;			\
			if ((tmp & FUTEX_ABORT_FLAG) ||		\
			    (tmp __cond (__v)))			\
				break;				\
			ret = sys_futex(&(__f)->raw, FUTEX_WAIT,\
					tmp, NULL, NULL, 0);	\
			if (ret < 0 && errno == EAGAIN)			\
				continue;			\
			BUG_ON(ret < 0 && errno != EWOULDBLOCK);	\
		}						\
	} while (0)

/* Set futex @f to @v and wake up all waiters */
static inline void futex_set_and_wake(futex_t *f, uint32_t v)
{
	atomic_set(&f->raw, v);
	BUG_ON(sys_futex(&f->raw, FUTEX_WAKE, INT_MAX, NULL, NULL, 0) < 0);
}

/* Mark futex @f as wait abort needed and wake up all waiters */
static inline void futex_abort_and_wake(futex_t *f)
{
	futex_set_and_wake(f, FUTEX_ABORT_RAW);
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
static inline void futex_wait_until(futex_t *f, uint32_t v)
{ futex_wait_if_cond(f, v, ==); }

/* Wait while futex @f value is greater than @v */
static inline void futex_wait_while_gt(futex_t *f, uint32_t v)
{ futex_wait_if_cond(f, v, <=); }

/* Wait while futex @f value is @v */
static inline uint32_t futex_wait_while(futex_t *f, uint32_t v)
{
	while (f->raw == v) {
		int ret = sys_futex(&f->raw, FUTEX_WAIT, v, NULL, NULL, 0);
		if (ret < 0 && errno == EAGAIN)
			continue;
		BUG_ON(ret < 0 && errno != EWOULDBLOCK);
	}

	return f->raw;
}

typedef struct {
	uint32_t	raw;
} mutex_t;

static void inline mutex_init(mutex_t *m)
{
	uint32_t c = 0;
	atomic_set(&m->raw, c);
}

static void inline mutex_lock(mutex_t *m)
{
	uint32_t c;
	int ret;

	while ((c = atomic_inc(&m->raw))) {
		ret = sys_futex(&m->raw, FUTEX_WAIT, c + 1, NULL, NULL, 0);
		BUG_ON(ret < 0 && ret != -EWOULDBLOCK);
	}
}

static void inline mutex_unlock(mutex_t *m)
{
	uint32_t c = 0;
	atomic_set(&m->raw, c);
	BUG_ON(sys_futex(&m->raw, FUTEX_WAKE, 1, NULL, NULL, 0) < 0);
}

#endif /* CR_LOCK_H_ */
