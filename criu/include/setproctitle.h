#ifndef __CR_SETPROCTITLE_H__
#define __CR_SETPROCTITLE_H__

#ifdef CONFIG_HAS_LIBBSD
#include <bsd/unistd.h>
#else

/*
 * setproctitle_init is in the libbsd since v0.6.0. This macro allows to
 * compile criu with libbsd<0.6.0.
 */
#ifndef CONFIG_HAS_SETPROCTITLE_INIT
#define setproctitle_init(argc, argv, envp)
#endif

#define setproctitle(fmt, ...)
#endif

#endif /* __CR_SETPROCTITLE_H__ */
