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
extern int collect_eventpoll(void);
extern void show_eventpoll(int fd);
extern void show_eventpoll_tfd(int fd);

#endif /* __CR_EVENTPOLL_H__ */
