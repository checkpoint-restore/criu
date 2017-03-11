#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>
#include "images/core.pb-c.h"

#include "page.h"
#include "bitops.h"
#include "asm/int.h"

#include <compel/plugins/std/asm/syscall-types.h>

typedef UserPpc64RegsEntry UserRegsEntry;

#define CORE_ENTRY__MARCH	CORE_ENTRY__MARCH__PPC64

#define core_is_compat(core)			false

#define CORE_THREAD_ARCH_INFO(core) core->ti_ppc64

static inline void *decode_pointer(uint64_t v) { return (void*)v; }
static inline uint64_t encode_pointer(void *p) { return (uint64_t)p; }

/*
 * Copied from the following kernel header files :
 * 	include/linux/auxvec.h
 *	arch/powerpc/include/uapi/asm/auxvec.h
 *	include/linux/mm_types.h
 */
#define AT_VECTOR_SIZE_BASE	20
#define AT_VECTOR_SIZE_ARCH	6
#define AT_VECTOR_SIZE		(2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

typedef uint64_t auxv_t;

/* Not used but the structure parasite_dump_thread needs a tls_t field */
typedef uint64_t tls_t;

#endif /* __CR_ASM_TYPES_H__ */
