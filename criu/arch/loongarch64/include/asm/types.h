#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>

#include "page.h"
#include "bitops.h"
#include "asm/int.h"
#include "images/core.pb-c.h"

#include <compel/plugins/std/asm/syscall-types.h>

#define core_is_compat(core) false

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__LOONGARCH64

#define CORE_THREAD_ARCH_INFO(core) core->ti_loongarch64

#define TI_SP(core) ((core)->ti_loongarch64->gpregs->regs[4])

#define TI_IP(core) ((core)->ti_loongarch64->gpregs->pc)

typedef UserLoongarch64GpregsEntry UserRegsEntry;

static inline uint64_t encode_pointer(void *p)
{
	return (uint64_t)p;
}
static inline void *decode_pointer(uint64_t v)
{
	return (void *)v;
}

#define AT_VECTOR_SIZE 44
typedef uint64_t auxv_t;
typedef uint64_t tls_t;

#endif /* __CR_ASM_TYPES_H__ */
