#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>
#include <asm/ptrace.h>
#include "images/core.pb-c.h"

#include "page.h"
#include "bitops.h"
#include "asm/int.h"

#include <compel/plugins/std/asm/syscall-types.h>

#define core_is_compat(core) false

typedef UserAarch64RegsEntry UserRegsEntry;

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__AARCH64

#define CORE_THREAD_ARCH_INFO(core) core->ti_aarch64

#define TI_SP(core) ((core)->ti_aarch64->gpregs->sp)

#define TI_IP(core) ((core)->ti_aarch64->gpregs->pc)

static inline void *decode_pointer(uint64_t v)
{
	return (void *)v;
}
static inline uint64_t encode_pointer(void *p)
{
	return (uint64_t)p;
}

/**
 * See also:
 *   * arch/arm64/include/uapi/asm/auxvec.h
 *   * include/linux/auxvec.h
 *   * include/linux/mm_types.h
 */
#define AT_VECTOR_SIZE_BASE 22
#define AT_VECTOR_SIZE_ARCH 2
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

typedef uint64_t auxv_t;
typedef uint64_t tls_t;

#endif /* __CR_ASM_TYPES_H__ */
