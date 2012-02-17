#ifndef LOG_H__
#define LOG_H__

extern int init_log(const char *name);
extern void fini_log(void);
extern int get_logfd(void);

#define LOG_ERROR	(0) /* Errors only */
#define LOG_WARN	(1) /* Informative */
#define LOG_DEBUG	(2) /* Debug ones */

extern void set_loglevel(unsigned int level);
extern void printk_level(unsigned int level, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));

#define printk(fmt, ...)	\
	printk_level(LOG_WARN, fmt, ##__VA_ARGS__)

#define pr_info(fmt, ...)	\
	printk_level(LOG_WARN,  fmt, ##__VA_ARGS__)

#define pr_err(fmt, ...)	\
	printk_level(LOG_ERROR, "Error (%s:%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_panic(fmt, ...)	\
	printk_level(LOG_ERROR, "Panic (%s:%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_warning(fmt, ...)	\
	printk_level(LOG_WARN,	"Warn  (%s:%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_debug(fmt, ...)	\
	printk_level(LOG_DEBUG,	fmt, ##__VA_ARGS__)

#define pr_perror(fmt, ...)	\
	pr_err(fmt ": %m\n", ##__VA_ARGS__)

#endif /* LOG_H__ */
