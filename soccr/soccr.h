#ifndef __LIBSOCCR_H__
#define __LIBSOCCR_H__
#include <linux/types.h>

struct libsoccr_sk;

void libsoccr_set_log(unsigned int level, void (*fn)(unsigned int level, const char *fmt, ...));

#define SOCCR_LOG_ERR	1
#define SOCCR_LOG_DBG	2

#endif
