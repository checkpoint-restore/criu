#ifndef __CR_EVENTPOLL_H__
#define __CR_EVENTPOLL_H__

#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "asm/types.h"
#include "files.h"
#include "crtools.h"

extern int is_eventpoll_link(int lfd);
extern const struct fdtype_ops eventpoll_dump_ops;
extern struct collect_image_info epoll_tfd_cinfo;
extern struct collect_image_info epoll_cinfo;

#endif /* __CR_EVENTPOLL_H__ */
