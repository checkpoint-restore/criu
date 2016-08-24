#ifndef __CR_LOG_H__
#define __CR_LOG_H__

#include <inttypes.h>

#include "criu-log.h"

extern int log_init(const char *output);
extern void log_fini(void);
extern int log_init_by_pid(void);
extern void log_closedir(void);
extern int log_keep_err(void);
extern char *log_first_err(void);

extern void log_set_fd(int fd);
extern int log_get_fd(void);

extern void log_set_loglevel(unsigned int loglevel);
extern unsigned int log_get_loglevel(void);

#define LOG_SIMPLE_CHUNK	72

extern int vprint_num(char *buf, int blen, int num, char **ps);
extern void simple_sprintf(char output[LOG_SIMPLE_CHUNK], const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));

extern int write_pidfile(int pid);

#define DEFAULT_LOGLEVEL	LOG_WARN

#define DEFAULT_LOG_FILENAME "criu.log"

struct cr_img;

extern void print_data(unsigned long addr, unsigned char *data, size_t size);
extern void print_image_data(struct cr_img *, unsigned int length, int show);

static inline int pr_quelled(unsigned int loglevel)
{
	return log_get_loglevel() < loglevel && loglevel != LOG_MSG;
}

#endif /* __CR_LOG_H__ */
