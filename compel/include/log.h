#ifndef COMPEL_LOG_H__
#define COMPEL_LOG_H__

#include <errno.h>
#include <string.h>

#include "uapi/compel/log.h"

#ifndef LOG_PREFIX
#define LOG_PREFIX
#endif

static inline int pr_quelled(unsigned int loglevel)
{
	return compel_log_get_loglevel() < loglevel && loglevel != COMPEL_LOG_MSG;
}

extern void compel_print_on_level(unsigned int loglevel, const char *format, ...)
	__attribute__((__format__(__printf__, 2, 3)));

#define pr_msg(fmt, ...) compel_print_on_level(COMPEL_LOG_MSG, fmt, ##__VA_ARGS__)

#define pr_info(fmt, ...) compel_print_on_level(COMPEL_LOG_INFO, LOG_PREFIX fmt, ##__VA_ARGS__)

#define pr_err(fmt, ...) \
	compel_print_on_level(COMPEL_LOG_ERROR, "Error (%s:%d): " LOG_PREFIX fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_err_once(fmt, ...)                       \
	do {                                        \
		static bool __printed;              \
		if (!__printed) {                   \
			pr_err(fmt, ##__VA_ARGS__); \
			__printed = 1;              \
		}                                   \
	} while (0)

#define pr_warn(fmt, ...) \
	compel_print_on_level(COMPEL_LOG_WARN, "Warn  (%s:%d): " LOG_PREFIX fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_warn_once(fmt, ...)                       \
	do {                                         \
		static bool __printed;               \
		if (!__printed) {                    \
			pr_warn(fmt, ##__VA_ARGS__); \
			__printed = 1;               \
		}                                    \
	} while (0)

#define pr_debug(fmt, ...) compel_print_on_level(COMPEL_LOG_DEBUG, LOG_PREFIX fmt, ##__VA_ARGS__)

#define pr_perror(fmt, ...) pr_err(fmt ": %s\n", ##__VA_ARGS__, strerror(errno))

#endif /* COMPEL_LOG_H__ */
