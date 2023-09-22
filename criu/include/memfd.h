#ifndef __CR_MEMFD_H__
#define __CR_MEMFD_H__

#include <stdbool.h>
#include <sys/stat.h>

#include "int.h"
#include "common/config.h"

struct fd_parms;
struct file_desc;

extern int is_memfd(dev_t dev);
extern int dump_one_memfd_cond(int lfd, u32 *id, struct fd_parms *parms);
extern const struct fdtype_ops memfd_dump_ops;

extern int memfd_open(struct file_desc *d, u32 *fdflags, bool filemap);
extern struct collect_image_info memfd_cinfo;
extern struct file_desc *collect_memfd(u32 id);
extern int apply_memfd_seals(void);

extern int prepare_memfd_inodes(void);

#ifdef CONFIG_HAS_MEMFD_CREATE
#include <sys/mman.h>
#else
#include <sys/syscall.h>
#include <linux/memfd.h>
static inline int memfd_create(const char *name, unsigned int flags)
{
	return syscall(SYS_memfd_create, name, flags);
}
#endif /* CONFIG_HAS_MEMFD_CREATE */

#endif /* __CR_MEMFD_H__ */
