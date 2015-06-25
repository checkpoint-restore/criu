#ifndef __CR_TIMERFD_H__
#define __CR_TIMERFD_H__

#include <time.h>
#include <sys/ioctl.h>

#include "files.h"

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

int rst_timerfd_prep(void);
extern unsigned long rst_timerfd_cpos;
extern unsigned int rst_timerfd_nr;


extern int check_timerfd(void);
extern int is_timerfd_link(char *link);

#ifndef TFD_TIMER_ABSTIME
# define TFD_TIMER_ABSTIME	(1 << 0)
#endif

#ifndef TFD_IOC_SET_TICKS
# define TFD_IOC_SET_TICKS	_IOW('T', 0, u64)
#endif

#endif /* __CR_TIMERFD_H__ */
