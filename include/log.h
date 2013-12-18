#ifndef __CR_LOG_H__
#define __CR_LOG_H__

#include "criu-log.h"

extern int log_init(const char *output);
extern void log_fini(void);
extern int log_init_by_pid(void);
extern void log_closedir(void);

extern void log_set_fd(int fd);
extern int log_get_fd(void);

extern void log_set_loglevel(unsigned int loglevel);
extern unsigned int log_get_loglevel(void);

extern int vprint_num(char *buf, int blen, int num, char **ps);

extern int write_pidfile(int pid);

#define DEFAULT_LOGLEVEL	LOG_WARN

#define DEFAULT_LOG_FILENAME "criu.log"

extern void print_data(unsigned long addr, unsigned char *data, size_t size);
extern void print_image_data(int fd, unsigned int length, int show);

#endif /* __CR_LOG_H__ */
