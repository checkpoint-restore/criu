#ifndef __CR_SETPROCTITLE_H__
#define __CR_SETPROCTITLE_H__

#ifdef CONFIG_HAS_LIBBSD
#include <bsd/unistd.h>
#else
#define setproctitle_init(argc, argv, envp)
#define setproctitle(fmt, ...)
#endif

#endif /* __CR_SETPROCTITLE_H__ */
