#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>

#include "page.h"
#include "bitops.h"
#include "asm/int.h"

#include <compel/plugins/std/asm/syscall-types.h>

#include "images/core.pb-c.h"

#define core_is_compat(core)			false

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__MIPS

#define CORE_THREAD_ARCH_INFO(core) core->ti_mips

typedef UserMipsRegsEntry UserRegsEntry;

static inline u64 encode_pointer(void *p) { return (u64)p; }
static inline void *decode_pointer(u64 v) { return (void*)v; }


#define AT_VECTOR_SIZE			44
typedef uint64_t auxv_t;

/*
 * Linux preserves three TLS segments in GDT.
 * Offsets in GDT differ between 32-bit and 64-bit machines.
 * For 64-bit x86 those GDT offsets are the same
 * for native and compat tasks.
 */
#define GDT_ENTRY_TLS_MIN		12
#define GDT_ENTRY_TLS_MAX		14
#define GDT_ENTRY_TLS_NUM		3
/*fixme :gysun*/
typedef unsigned long tls_t;

#endif /* __CR_ASM_TYPES_H__ */
