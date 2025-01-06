#ifndef __CR_STRING_H__
#define __CR_STRING_H__

#include <sys/types.h>

#include "common/config.h"

extern size_t __strlcpy(char *dest, const char *src, size_t size);
extern size_t __strlcat(char *dest, const char *src, size_t count);

#endif /* __CR_STRING_H__ */
