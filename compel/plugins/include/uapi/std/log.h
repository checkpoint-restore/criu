#ifndef COMPEL_PLUGIN_STD_LOG_H__
#define COMPEL_PLUGIN_STD_LOG_H__

#include "compel/loglevels.h"
#include "common/compiler.h"

#define STD_LOG_SIMPLE_CHUNK 256

extern void std_log_set_fd(int fd);
extern void std_log_set_loglevel(enum __compel_log_levels level);
extern void std_log_set_start(struct timeval *tv);

/*
 * Provides a function to get time *in the infected task* for log timings.
 * Expected use-case: address on the vdso page to get time.
 * If not set or called with NULL - compel will use raw syscall,
 * which requires enter in the kernel and as a result affects performance.
 */
typedef int (*gettimeofday_t)(struct timeval *tv, struct timezone *tz);
extern void std_log_set_gettimeofday(gettimeofday_t gtod);
/* std plugin helper to get time (hopefully, efficiently) */
extern int std_gettimeofday(struct timeval *tv, struct timezone *tz);

extern int std_vprint_num(char *buf, int blen, int num, char **ps);
extern void std_sprintf(char output[STD_LOG_SIMPLE_CHUNK], const char *format, ...)
	__attribute__((__format__(__printf__, 2, 3)));
extern void print_on_level(unsigned int loglevel, const char *format, ...)
	__attribute__((__format__(__printf__, 2, 3)));

#endif /* COMPEL_PLUGIN_STD_LOG_H__ */
