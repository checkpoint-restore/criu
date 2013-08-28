#ifndef __CR_STRING_H__
#define __CR_STRING_H__

#include <sys/types.h>
#include <string.h>

#include "config.h"

#ifndef CONFIG_HAS_STRLCPY
extern size_t strlcpy(char *dest, const char *src, size_t size);
#endif

#endif /* __CR_STRING_H__ */
