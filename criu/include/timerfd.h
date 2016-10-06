#ifndef __CR_TIMERFD_H__
#define __CR_TIMERFD_H__

#include <time.h>
#include <sys/ioctl.h>

#include "files.h"

#include "images/timerfd.pb-c.h"

struct pstree_item;

struct restore_timerfd {
	int			id;
	int			fd;
	int			clockid;
	int			settime_flags;
	unsigned long		ticks;
	struct itimerspec	val;
};

extern const struct fdtype_ops timerfd_dump_ops;
extern struct collect_image_info timerfd_cinfo;

struct task_restore_args;
int prepare_timerfds(struct task_restore_args *);

extern int check_timerfd(void);
extern int is_timerfd_link(char *link);

#ifndef TFD_TIMER_ABSTIME
# define TFD_TIMER_ABSTIME	(1 << 0)
#endif

#ifndef TFD_IOC_SET_TICKS
# define TFD_IOC_SET_TICKS	_IOW('T', 0, u64)
#endif

static inline int verify_timerfd(TimerfdEntry *tfe)
{
	if (tfe->clockid != CLOCK_REALTIME &&
	    tfe->clockid != CLOCK_BOOTTIME &&
	    tfe->clockid != CLOCK_MONOTONIC) {
		pr_err("Unknown clock type %d for %#x\n", tfe->clockid, tfe->id);
		return -1;
	}

	return 0;
}


#endif /* __CR_TIMERFD_H__ */
