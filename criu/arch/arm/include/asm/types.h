#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>
#include "images/core.pb-c.h"

#include "page.h"
#include "bitops.h"
#include "asm/int.h"

#include <compel/plugins/std/asm/syscall-types.h>

#define core_is_compat(core) false

typedef UserArmRegsEntry UserRegsEntry;

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__ARM

#define CORE_THREAD_ARCH_INFO(core) core->ti_arm

#define TI_SP(core) ((core)->ti_arm->gpregs->sp)

static inline void *decode_pointer(u64 v)
{
	return (void *)(u32)v;
}
static inline u64 encode_pointer(void *p)
{
	return (u32)p;
}

#define AT_VECTOR_SIZE 40
typedef uint32_t auxv_t;
typedef uint32_t tls_t;

#endif /* __CR_ASM_TYPES_H__ */
