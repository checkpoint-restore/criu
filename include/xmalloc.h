#ifndef __CR_XMALLOC_H__
#define __CR_XMALLOC_H__

#include <stdlib.h>
#include <string.h>

#include "log.h"

#define __xalloc(op, size, ...)						\
	({								\
		void *___p = op( __VA_ARGS__ );				\
		if (!___p)						\
			pr_err("%s: Can't allocate %li bytes\n",	\
			       __func__, (long)(size));			\
		___p;							\
	})

#define xstrdup(str)		__xalloc(strdup, strlen(str) + 1, str)
#define xmalloc(size)		__xalloc(malloc, size, size)
#define xzalloc(size)		__xalloc(calloc, size, 1, size)
#define xrealloc(p, size)	__xalloc(realloc, size, p, size)

#define xfree(p)		do { if (p) free(p); } while (0)

#define xrealloc_safe(pptr, size)					\
	({								\
		int __ret = -1;						\
		void *new = xrealloc(*pptr, size);			\
		if (new) {						\
			*pptr = new;					\
			__ret = 0;					\
		}							\
		__ret;							\
	 })

#define memzero_p(p)		memset(p, 0, sizeof(*p))
#define memzero(p, size)	memset(p, 0, size)

#endif /* __CR_XMALLOC_H__ */
