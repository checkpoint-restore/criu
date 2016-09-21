#ifndef COMPEL_PLUGIN_STD_STRING_H__
#define COMPEL_PLUGIN_STD_STRING_H__

#include <sys/types.h>
#include <stdbool.h>
#include <stdarg.h>

/* Standard file descriptors.  */
#define	STDIN_FILENO	0	/* Standard input.  */
#define	STDOUT_FILENO	1	/* Standard output.  */
#define	STDERR_FILENO	2	/* Standard error output.  */


extern void __std_putc(int fd, char c);
extern void __std_puts(int fd, const char *s);
extern void __std_printk(int fd, const char *format, va_list args);
extern void __std_printf(int fd, const char *format, ...);

#define std_printf(fmt, ...)	__std_printf(STDOUT_FILENO, fmt, ##__VA_ARGS__)
#define std_puts(s)		__std_puts(STDOUT_FILENO, s)
#define std_putchar(c)		__std_putc(STDOUT_FILENO, c)

extern unsigned long std_strtoul(const char *nptr, char **endptr, int base);
extern void *std_memcpy(void *to, const void *from, unsigned int n);
extern int std_memcmp(const void *cs, const void *ct, size_t count);
extern int std_strcmp(const char *cs, const char *ct);

#endif /* COMPEL_PLUGIN_STD_STRING_H__ */
