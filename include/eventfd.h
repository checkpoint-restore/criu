#ifndef __CR_EVENTFD_H__
#define __CR_EVENTFD_H__

#include "files.h"

extern int is_eventfd_link(char *link);
extern const struct fdtype_ops eventfd_dump_ops;
extern struct collect_image_info eventfd_cinfo;

#endif /* __CR_EVENTFD_H__ */
