#ifndef COMPEL_PLUGIN_STD_LOG_H__
#define COMPEL_PLUGIN_STD_LOG_H__

#define STD_LOG_SIMPLE_CHUNK	79

extern void std_log_set_fd(int fd);
extern void std_log_set_loglevel(unsigned int level);
extern void std_log_set_start(struct timeval *tv);
extern int std_vprint_num(char *buf, int blen, int num, char **ps);
extern void std_sprintf(char output[STD_LOG_SIMPLE_CHUNK], const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
extern void print_on_level(unsigned int loglevel, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));

#endif /* COMPEL_PLUGIN_STD_LOG_H__ */
