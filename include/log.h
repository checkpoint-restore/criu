#ifndef LOG_H__
#define LOG_H__

extern int log_init(const char *output);
extern void log_fini(void);
extern int log_init_by_pid(void);

extern int log_get_fd(void);

extern void log_set_loglevel(unsigned int loglevel);

extern void print_on_level(unsigned int loglevel, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));

#define LOG_MSG		(0) /* Print message regardless of log level */
#define LOG_ERROR	(1) /* Errors only, when we're in trouble */
#define LOG_WARN	(2) /* Warnings, dazen and confused but trying to continue */
#define LOG_INFO	(3) /* Informative, everything is fine */
#define LOG_DEBUG	(4) /* Debug only */

#define pr_msg(fmt, ...)	\
	print_on_level(LOG_MSG,		fmt, ##__VA_ARGS__)

#define pr_info(fmt, ...)	\
	print_on_level(LOG_INFO,	fmt, ##__VA_ARGS__)

#define pr_err(fmt, ...)	\
	print_on_level(LOG_ERROR,	"Error (%s:%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_warn(fmt, ...)	\
	print_on_level(LOG_WARN,	"Warn  (%s:%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_debug(fmt, ...)	\
	print_on_level(LOG_DEBUG,	fmt, ##__VA_ARGS__)

#define pr_perror(fmt, ...)	\
	pr_err(fmt ": %m\n", ##__VA_ARGS__)

#endif /* LOG_H__ */
