#ifndef __CR_MEMFD_H__
#define __CR_MEMFD_H__

#include <sys/stat.h>
#include "int.h"
#include "common/config.h"

extern int is_memfd(dev_t dev, const char *path);
extern const struct fdtype_ops memfd_dump_ops;

extern struct collect_image_info memfd_cinfo;

#ifdef CONFIG_HAS_MEMFD_CREATE
# include <sys/mman.h>
#else
# include <sys/syscall.h>
# include <linux/memfd.h>
static inline int memfd_create(const char *name, unsigned int flags)
{
	return syscall(SYS_memfd_create, name, flags);
}
#endif /* CONFIG_HAS_MEMFD_CREATE */

#endif /* __CR_MEMFD_H__ */
