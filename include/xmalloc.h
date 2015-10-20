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

#define xfree(p)		free(p)

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

/*
 * Helper for allocating trees with single xmalloc.
 * This one advances the void *pointer on s bytes and
 * returns the previous value. Use like this
 *
 * m = xmalloc(total_size);
 * a = xptr_pull(&m, tree_root_t);
 * a->b = xptr_pull(&m, leaf_a_t);
 * a->c = xptr_pull(&m, leaf_c_t);
 * ...
 */
static inline void *xptr_pull_s(void **m, size_t s)
{
	void *ret = (*m);
	(*m) += s;
	return ret;
}

#define xptr_pull(m, type)	xptr_pull_s(m, sizeof(type))

#endif /* __CR_XMALLOC_H__ */
