/*
 * Adopted from linux kernel
 */
#ifndef __CR_COMMON_ERR_H__
#define __CR_COMMON_ERR_H__

#include "common/compiler.h"

/*
 * The address of a block returned by malloc or realloc in GNU
 * systems is always a multiple of eight (or sixteen on 64-bit systems).
 *
 * Thus we may encode error number in low bits.
 */
#define MAX_ERRNO 4095

#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

static inline void *ERR_PTR(long error)
{
	return (void *)error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

static inline long IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline long IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

static inline void *ERR_CAST(const void *ptr)
{
	/* cast away the const */
	return (void *)ptr;
}

static inline int PTR_RET(const void *ptr)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	else
		return 0;
}

#endif /* __CR_ERR_H__ */
