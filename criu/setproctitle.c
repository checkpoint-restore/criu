#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef CONFIG_HAS_LIBBSD
#include <bsd/unistd.h>
#else

#include "setproctitle.h"

/*
 * setproctitle_init is in the libbsd since v0.6.0. This macro allows to
 * compile criu with libbsd<0.6.0.
 */
#ifndef CONFIG_HAS_SETPROCTITLE_INIT
#define setproctitle_init(argc, argv, envp)
#endif

#define setproctitle(fmt, ...)
#endif

void __setproctitle_init(int argc, char *argv[], char *envp[])
{
	setproctitle_init(argc, argv, envp);
}

#ifndef SPT_MAXTITLE
#define SPT_MAXTITLE 255
#endif

void __setproctitle(const char *fmt, ...)
{
	char buf[SPT_MAXTITLE + 1];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	setproctitle("%s", buf);
}
