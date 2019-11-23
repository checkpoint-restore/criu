#ifndef __CR_LIB_BSD_H__
#define __CR_LIB_BSD_H__

#include <stddef.h> /* size_t */

extern size_t strlcpy(char *dest, const char *src, size_t size);
extern size_t strlcat(char *dest, const char *src, size_t count);
extern void setproctitle_init(int argc, char *argv[], char *envp[]);
extern void setproctitle(const char *fmt, ...);

#endif /* __CR_LIB_BSD_H__ */
