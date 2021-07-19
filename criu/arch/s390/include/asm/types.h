#ifndef _UAPI_S390_TYPES_H
#define _UAPI_S390_TYPES_H

#include <stdbool.h>
#include <signal.h>
#include "images/core.pb-c.h"

#include "page.h"
#include "bitops.h"
#include "asm/int.h"

#include <compel/plugins/std/asm/syscall-types.h>

typedef UserS390RegsEntry UserRegsEntry;

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__S390

#define core_is_compat(core) false

#define CORE_THREAD_ARCH_INFO(core) core->ti_s390

static inline u64 encode_pointer(void *p)
{
	return (u64)p;
}
static inline void *decode_pointer(u64 v)
{
	return (void *)v;
}

/*
 * See also:
 *   * arch/s390/include/uapi/asm/auxvec.h
 *   * include/linux/auxvec.h
 */
#define AT_VECTOR_SIZE_BASE 20
#define AT_VECTOR_SIZE_ARCH 1
#define AT_VECTOR_SIZE	    (2 * (AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

typedef uint64_t auxv_t;
typedef uint64_t tls_t;

#endif /* _UAPI_S390_TYPES_H */
