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

/*
 * Init futex @v value
 */
static always_inline void cr_wait_init(u32 *v)
{
	u32 val = 0;
	atomic_set(v, val);
}

/*
 * Set futex @v value to @val and wake up all waiters
 */
static always_inline void cr_wait_set(u32 *v, u32 val)
{
	int ret;

	atomic_set(v, val);

	ret = sys_futex(v, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
	BUG_ON(ret < 0);
}

/*
 * Decrement futex @v value to @val and wake up all waiters
 */
static always_inline void cr_wait_dec(u32 *v)
{
	int ret;

	atomic_dec(v);

	ret = sys_futex(v, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
	BUG_ON(ret < 0);
}

/*
 * Wait until futex @v value become @val
 */
static always_inline void cr_wait_until(u32 *v, u32 val)
{
	int ret;
	u32 tmp;

	while (1) {
		tmp = *v;
		if (tmp == val)
			break;
		ret = sys_futex(v, FUTEX_WAIT, tmp, NULL, NULL, 0);
		BUG_ON(ret < 0 && ret != -EWOULDBLOCK);
	}
}

/*
 * Wait until futex @v value greater than @val
 */
static always_inline s32 cr_wait_until_greater(u32 *v, s32 val)
{
	int ret;
	s32 tmp;

	while (1) {
		tmp = *v;
		if (tmp <= val)
			break;
		ret = sys_futex(v, FUTEX_WAIT, tmp, NULL, NULL, 0);
		BUG_ON(ret < 0 && ret != -EWOULDBLOCK);
	}

	return tmp;
}

/*
 * Wait while futex @v value is @val
 */
static always_inline void cr_wait_while(u32 *v, u32 val)
{
	int ret;

	while (*v == val) {
		ret = sys_futex(v, FUTEX_WAIT, val, NULL, NULL, 0);
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
