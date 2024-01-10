#ifndef __CR_MEMFD_SECRET_H__
#define __CR_MEMFD_SECRET_H__

#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

#include "common/config.h"

extern int is_memfd_secret(dev_t dev);
extern const struct fdtype_ops memfd_secret_dump_ops;
extern struct collect_image_info memfd_secret_cinfo;

static inline int memfd_secret(unsigned int flags)
{
#ifdef __NR_memfd_secret
	return syscall(__NR_memfd_secret, flags);
#else
	errno = ENOSYS;
	return -1;
#endif /* __NR_memfd_secret */
}

#endif /* __CR_MEMFD_SECRET_H__ */
