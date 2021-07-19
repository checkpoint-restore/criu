#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>

#include "page.h"
#include "bitops.h"
#include "asm/int.h"

#include <compel/plugins/std/asm/syscall-types.h>

#include "images/core.pb-c.h"

static inline int core_is_compat(CoreEntry *c)
{
	switch (c->thread_info->gpregs->mode) {
	case USER_X86_REGS_MODE__NATIVE:
		return 0;
	case USER_X86_REGS_MODE__COMPAT:
		return 1;
	default:
		return -1;
	}
}

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__X86_64

#define CORE_THREAD_ARCH_INFO(core) core->thread_info

typedef UserX86RegsEntry UserRegsEntry;

static inline u64 encode_pointer(void *p)
{
	return (u64)(long)p;
}
static inline void *decode_pointer(u64 v)
{
	return (void *)(long)v;
}

#define AT_VECTOR_SIZE 44
typedef uint64_t auxv_t;

#endif /* __CR_ASM_TYPES_H__ */
