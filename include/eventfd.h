#ifndef __CR_EVENTFD_H__
#define __CR_EVENTFD_H__

#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "asm/types.h"
#include "files.h"
#include "crtools.h"

extern int is_eventfd_link(int lfd);
extern const struct fdtype_ops eventfd_dump_ops;
extern struct collect_image_info eventfd_cinfo;

#endif /* __CR_EVENTFD_H__ */
