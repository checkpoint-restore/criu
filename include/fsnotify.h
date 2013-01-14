#ifndef __CR_FSNOTIFY_H__
#define __CR_FSNOTIFY_H__

#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "asm/types.h"
#include "files.h"
#include "crtools.h"

struct fsnotify_params {
	u32	id;
	u32	faflags;
	u32	evflags;
};

extern int is_inotify_link(int lfd);
extern int is_fanotify_link(int lfd);
extern int dump_inotify(struct fd_parms *p, int lfd, const int fdinfo);
extern int dump_fanotify(struct fd_parms *p, int lfd, const int fdinfo);
extern int collect_inotify(void);
extern void show_inotify_wd(int fd_inotify_wd, struct cr_options *o);
extern void show_inotify(int fd_inotify, struct cr_options *o);
extern void show_fanotify_mark(int fd, struct cr_options *o);
extern void show_fanotify(int fd, struct cr_options *o);

#endif /* __CR_FSNOTIFY_H__ */
