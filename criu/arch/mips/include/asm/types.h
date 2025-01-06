#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>

#include "page.h"
#include "bitops.h"
#include "asm/int.h"

#include <compel/plugins/std/asm/syscall-types.h>

#include "images/core.pb-c.h"

#define core_is_compat(core) false

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__MIPS

#define CORE_THREAD_ARCH_INFO(core) core->ti_mips

#define TI_IP(core) ((core)->ti_mips->gpregs->cp0_epc)

typedef UserMipsRegsEntry UserRegsEntry;

static inline u64 encode_pointer(void *p)
{
	return (u64)p;
}
static inline void *decode_pointer(u64 v)
{
	return (void *)v;
}

#define AT_VECTOR_SIZE 44
typedef uint64_t auxv_t;
typedef unsigned long tls_t;

#endif /* __CR_ASM_TYPES_H__ */
