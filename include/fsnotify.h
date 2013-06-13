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
extern const struct fdtype_ops inotify_dump_ops;
extern const struct fdtype_ops fanotify_dump_ops;
extern int collect_inotify(void);
extern void show_inotify_wd(int fd);
extern void show_inotify(int fd);
extern void show_fanotify_mark(int fd);
extern void show_fanotify(int fd);

#endif /* __CR_FSNOTIFY_H__ */
