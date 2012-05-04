#ifndef INOTIFY_H__
#define INOTIFY_H__

#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "types.h"
#include "files.h"
#include "crtools.h"

extern int is_inotify_link(int lfd);
extern int dump_inotify(struct fd_parms *p, int lfd, const struct cr_fdset *set);
extern int collect_inotify(void);
extern void show_inotify_wd(int fd_inotify_wd, struct cr_options *o);
extern void show_inotify(int fd_inotify, struct cr_options *o);

#endif /* INOTIFY_H__ */
