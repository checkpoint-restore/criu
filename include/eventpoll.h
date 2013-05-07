#ifndef __CR_EVENTPOLL_H__
#define __CR_EVENTPOLL_H__

#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "asm/types.h"
#include "files.h"
#include "crtools.h"

extern int is_eventpoll_link(int lfd);
extern int dump_eventpoll(struct fd_parms *p, int lfd, const int fdinfo);
extern int collect_eventpoll(void);
extern void show_eventpoll(int fd);
extern void show_eventpoll_tfd(int fd);

#endif /* __CR_EVENTPOLL_H__ */
