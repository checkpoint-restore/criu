#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>
#include "images/core.pb-c.h"

#include "page.h"
#include "bitops.h"
#include "asm/int.h"

/*
 * Copied from kernel header include/uapi/asm-generic/signal-defs.h
 */
typedef void rt_signalfn_t(int, siginfo_t *, void *);
typedef rt_signalfn_t *rt_sighandler_t;

typedef void rt_restorefn_t(void);
typedef rt_restorefn_t *rt_sigrestore_t;

/*Copied from the Linux kernel arch/powerpc/include/uapi/asm/signal.h */
#define _KNSIG		64
#define _NSIG_BPW       64
#define _KNSIG_WORDS     (_KNSIG / _NSIG_BPW)

typedef struct {
        uint64_t sig[_KNSIG_WORDS];
} k_rtsigset_t;

/* Copied from the Linux kernel arch/powerpc/include/uapi/asm/signal.h */
#define SA_RESTORER     0x04000000U

typedef struct {
        rt_sighandler_t rt_sa_handler;
        unsigned long rt_sa_flags;
        rt_sigrestore_t rt_sa_restorer;
        k_rtsigset_t rt_sa_mask;               /* mask last for extensibility */
} rt_sigaction_t;

typedef UserPpc64RegsEntry UserRegsEntry;

#define CORE_ENTRY__MARCH	CORE_ENTRY__MARCH__PPC64


#define CORE_THREAD_ARCH_INFO(core) core->ti_ppc64

static inline void *decode_pointer(uint64_t v) { return (void*)v; }
static inline uint64_t encode_pointer(void *p) { return (uint64_t)p; }

#endif /* __CR_ASM_TYPES_H__ */
