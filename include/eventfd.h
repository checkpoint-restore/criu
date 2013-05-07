#ifndef __CR_EVENTFD_H__
#define __CR_EVENTFD_H__

#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "asm/types.h"
#include "files.h"
#include "crtools.h"

extern int is_eventfd_link(int lfd);
extern int dump_eventfd(struct fd_parms *p, int lfd, const int fdinfo);
extern int collect_eventfd(void);
extern void show_eventfds(int fd);

#endif /* __CR_EVENTFD_H__ */
