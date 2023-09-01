#ifndef __CR_PIDFD_H__
#define __CR_PIDFD_H__

#include <sys/stat.h>
#include "images/pidfd.pb-c.h"
#include <sys/syscall.h>
#include <unistd.h>

struct fd_parms;

extern const struct fdtype_ops pidfd_dump_ops;
extern struct collect_image_info pidfd_cinfo;
extern int is_pidfd_link(char *link);

static inline int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}
#endif
