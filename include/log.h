#ifndef LOG_H__
#define LOG_H__

extern void printk(const char *format, ...) __attribute__ ((__format__ (__printf__, 1, 2)));

extern int init_log(const char *name);
extern void fini_log(void);
extern int get_logfd(void);

#define pr_info(fmt, ...)	printk(fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)	printk("Error (%s:%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define pr_panic(fmt, ...)	printk("PANIC (%s:%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define pr_warning(fmt, ...)	printk("Warning (%s:%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#ifdef CR_DEBUG
#define pr_debug(fmt, ...)					\
	do {							\
		printk("%s:%d:%s: " fmt,			\
		       __FILE__, __LINE__,__func__,		\
		       ##__VA_ARGS__);				\
	} while (0)
#define dprintk(fmt, ...)	printk(fmt, ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...)
#define dprintk(fmt, ...)
#endif

#define die(fmt, ...)						\
	do {							\
		printk("die (%s:%d): " fmt, __FILE__,		\
			__LINE__, ##__VA_ARGS__);		\
		exit(1);					\
	} while (0)

#define pr_perror(fmt, ...)					\
	do {							\
		pr_err(fmt ": %m\n", ##__VA_ARGS__);		\
	} while (0)

#endif /* LOG_H__ */
