#ifndef __CR_PIE_TIME_H__
#define __CR_PIE_TIME_H__

#include <time.h>
#include <sys/time.h>

#include <compel/plugins/std/syscall.h>

/*
 * Raw time syscalls for the parasite and the restorer.
 *
 * On 32-bit arm, a build with 64-bit time_t (Debian armhf since trixie,
 * Yocto since scarthgap, musl) has a struct timespec that no longer
 * matches what the old timer syscalls use, so call the *_time64 ones.
 */
#ifdef __arm__
#define CR_TIME64 (sizeof(time_t) > sizeof(long))
#endif

static inline long cr_clock_gettime(clockid_t clk, struct timespec *ts)
{
#ifdef CR_TIME64
	if (CR_TIME64)
		return sys_clock_gettime64(clk, ts);
#endif
	return sys_clock_gettime(clk, ts);
}

static inline long cr_timer_gettime(int id, struct itimerspec *val)
{
#ifdef CR_TIME64
	if (CR_TIME64)
		return sys_timer_gettime64(id, val);
#endif
	return sys_timer_gettime(id, val);
}

static inline long cr_timer_settime(kernel_timer_t id, int flags, const struct itimerspec *val)
{
#ifdef CR_TIME64
	if (CR_TIME64)
		return sys_timer_settime64(id, flags, val, NULL);
#endif
	return sys_timer_settime(id, flags, val, NULL);
}

static inline long cr_timerfd_settime(int fd, int flags, const struct itimerspec *val)
{
#ifdef CR_TIME64
	if (CR_TIME64)
		return sys_timerfd_settime64(fd, flags, val, NULL);
#endif
	return sys_timerfd_settime(fd, flags, val, NULL);
}

/*
 * getitimer() and setitimer() have no 64-bit time variant, the kernel
 * always uses longs here. On 64-bit arches this is struct itimerval.
 */
struct kernel_itimerval {
	struct {
		long tv_sec;
		long tv_usec;
	} it_interval, it_value;
};

static inline long cr_getitimer(int which, struct itimerval *val)
{
	struct kernel_itimerval k = {};
	long ret;

	ret = sys_getitimer(which, (void *)&k);
	if (ret)
		return ret;

	val->it_interval.tv_sec = k.it_interval.tv_sec;
	val->it_interval.tv_usec = k.it_interval.tv_usec;
	val->it_value.tv_sec = k.it_value.tv_sec;
	val->it_value.tv_usec = k.it_value.tv_usec;
	return 0;
}

static inline long cr_setitimer(int which, const struct itimerval *val)
{
	struct kernel_itimerval k = {
		.it_interval = { val->it_interval.tv_sec, val->it_interval.tv_usec },
		.it_value = { val->it_value.tv_sec, val->it_value.tv_usec },
	};

	return sys_setitimer(which, (void *)&k, NULL);
}

#endif /* __CR_PIE_TIME_H__ */
