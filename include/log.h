#ifndef __CR_LOG_H__
#define __CR_LOG_H__

#include "log-levels.h"

extern int log_init(const char *output);
extern void log_fini(void);
extern int log_init_by_pid(void);
extern void log_closedir(void);

extern void log_set_fd(int fd);
extern int log_get_fd(void);

extern void log_set_loglevel(unsigned int loglevel);
extern unsigned int log_get_loglevel(void);

extern int vprint_num(char *buf, int blen, int num, char **ps);

extern void print_on_level(unsigned int loglevel, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));

extern int write_pidfile(int pid);

#ifndef LOG_PREFIX
# define LOG_PREFIX
#endif

#define pr_msg(fmt, ...)							\
	print_on_level(LOG_MSG,							\
		       fmt, ##__VA_ARGS__)

#define pr_info(fmt, ...)							\
	print_on_level(LOG_INFO,						\
		       LOG_PREFIX fmt, ##__VA_ARGS__)

#define pr_err(fmt, ...)							\
	print_on_level(LOG_ERROR,						\
		       "Error (%s:%d): " LOG_PREFIX fmt,			\
		       __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_err_once(fmt, ...)							\
	do {									\
		static bool __printed;						\
		if (!__printed) {						\
			pr_err(fmt, ##__VA_ARGS__);				\
			__printed = 1;						\
		}								\
	} while (0)

#define pr_warn(fmt, ...)							\
	print_on_level(LOG_WARN,						\
		       "Warn  (%s:%d): " LOG_PREFIX fmt,			\
		       __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_debug(fmt, ...)							\
	print_on_level(LOG_DEBUG,						\
		       LOG_PREFIX fmt, ##__VA_ARGS__)

#define pr_perror(fmt, ...)							\
	pr_err(fmt ": %m\n", ##__VA_ARGS__)

#define DEFAULT_LOG_FILENAME "criu.log"

extern void print_data(unsigned long addr, unsigned char *data, size_t size);
extern void print_image_data(int fd, unsigned int length, int show);

#endif /* __CR_LOG_H__ */
