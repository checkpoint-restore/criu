#ifndef COMPEL_PLUGIN_STD_STRING_H__
#define COMPEL_PLUGIN_STD_STRING_H__

#include <sys/types.h>
#include <stdbool.h>
#include <stdarg.h>

/* Standard file descriptors.  */
#define STDIN_FILENO  0 /* Standard input.  */
#define STDOUT_FILENO 1 /* Standard output.  */
#define STDERR_FILENO 2 /* Standard error output.  */

extern void std_dputc(int fd, char c);
extern void std_dputs(int fd, const char *s);
extern void std_vdprintf(int fd, const char *format, va_list args);
extern void std_dprintf(int fd, const char *format, ...) __attribute__((__format__(__printf__, 2, 3)));

#define std_printf(fmt, ...) std_dprintf(STDOUT_FILENO, fmt, ##__VA_ARGS__)
#define std_puts(s)	     std_dputs(STDOUT_FILENO, s)
#define std_putchar(c)	     std_dputc(STDOUT_FILENO, c)

extern unsigned long std_strtoul(const char *nptr, char **endptr, int base);
extern int std_strcmp(const char *cs, const char *ct);
extern int std_strncmp(const char *cs, const char *ct, size_t n);

extern void *memcpy(void *dest, const void *src, size_t n);
extern int memcmp(const void *s1, const void *s2, size_t n);
extern void *memset(void *s, int c, size_t n);

#endif /* COMPEL_PLUGIN_STD_STRING_H__ */
