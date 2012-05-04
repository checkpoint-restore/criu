#ifndef EVENTFD_H__
#define EVENTFD_H__

#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "types.h"
#include "files.h"
#include "crtools.h"

extern int is_eventfd_link(int lfd);
extern int dump_eventfd(struct fd_parms *p, int lfd, const struct cr_fdset *set);
extern int collect_eventfd(void);
extern void show_eventfds(int fd, struct cr_options *o);

#endif /* EVENTFD_H__ */
