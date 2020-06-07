#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

#define pr_out(fmt, ...)	fprintf(stdout, fmt, ##__VA_ARGS__)

#if 1
# define pr_debug(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)
#else
# define pr_debug(fmt, ...)
#endif

#define pr_err(fmt, ...)	fprintf(stderr, "Error (%s:%d): "fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define pr_perror(fmt, ...)	fprintf(stderr, "Error (%s:%d): "fmt "%m\n", __FILE__, __LINE__, ##__VA_ARGS__)

#endif /* __LOG_H__ */
