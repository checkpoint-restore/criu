#ifndef __CR_CRIU_LOG_H__
#define __CR_CRIU_LOG_H__

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define LOG_UNSET  (-1)
#define LOG_MSG    0
#define LOG_ERROR  1
#define LOG_WARN   2
#define LOG_INFO   3
#define LOG_DEBUG  4

#define pr_msg(fmt, ...)    fprintf(stdout, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)   do {} while (0)
#define pr_debug(fmt, ...)  do {} while (0)
#define pr_err(fmt, ...)    fprintf(stderr, "ERR: " fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)   fprintf(stderr, "WARN: " fmt, ##__VA_ARGS__)
#define pr_perror(fmt, ...) fprintf(stderr, "ERR: " fmt ": %s\n", ##__VA_ARGS__, strerror(errno))

static inline void print_on_level(unsigned int loglevel, const char *format, ...)
{
	(void)loglevel;
	(void)format;
}

#endif /* __CR_CRIU_LOG_H__ */
