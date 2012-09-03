#ifndef LOG_H__
#define LOG_H__

#include "log-levels.h"

extern int log_init(const char *output);
extern void log_fini(void);
extern int log_init_by_pid(void);
extern void log_closedir(void);

extern int log_get_fd(void);

extern void log_set_loglevel(unsigned int loglevel);
extern unsigned int log_get_loglevel(void);

extern void print_on_level(unsigned int loglevel, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));

#ifndef LOG_PREFIX
# define LOG_PREFIX
#endif

#define pr_msg(fmt, ...)	\
	print_on_level(LOG_MSG,		fmt, ##__VA_ARGS__)

#define pr_info(fmt, ...)	\
	print_on_level(LOG_INFO,	LOG_PREFIX fmt, ##__VA_ARGS__)

#define pr_err(fmt, ...)	\
	print_on_level(LOG_ERROR,	"Error (%s:%d): " LOG_PREFIX fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_warn(fmt, ...)	\
	print_on_level(LOG_WARN,	"Warn  (%s:%d): " LOG_PREFIX fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_debug(fmt, ...)	\
	print_on_level(LOG_DEBUG,	LOG_PREFIX fmt, ##__VA_ARGS__)

#define pr_perror(fmt, ...)	\
	pr_err(fmt ": %m\n", ##__VA_ARGS__)

#endif /* LOG_H__ */
