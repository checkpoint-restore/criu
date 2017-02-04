#ifndef __CR_STRING_H__
#define __CR_STRING_H__

#include <sys/types.h>
#include <string.h>

#ifdef CONFIG_HAS_LIBBSD
# include <bsd/string.h>
#endif

#include "config.h"

#ifndef CONFIG_HAS_STRLCPY
extern size_t strlcpy(char *dest, const char *src, size_t size);
#endif

#ifndef CONFIG_HAS_STRLCAT
extern size_t strlcat(char *dest, const char *src, size_t count);
#endif

extern int builtin_strncmp(const char *cs, const char *ct, size_t count);

#endif /* __CR_STRING_H__ */
