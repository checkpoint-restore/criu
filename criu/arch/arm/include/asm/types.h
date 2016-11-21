#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>
#include "images/core.pb-c.h"

#include "page.h"
#include "bitops.h"
#include "asm/int.h"

typedef void rt_signalfn_t(int, siginfo_t *, void *);
typedef rt_signalfn_t *rt_sighandler_t;

typedef void rt_restorefn_t(void);
typedef rt_restorefn_t *rt_sigrestore_t;

#define _KNSIG		64
#define _NSIG_BPW	32

#define _KNSIG_WORDS	(_KNSIG / _NSIG_BPW)

typedef struct {
	unsigned long sig[_KNSIG_WORDS];
} k_rtsigset_t;

#define SA_RESTORER	0x04000000

typedef struct {
	rt_sighandler_t	rt_sa_handler;
	unsigned long	rt_sa_flags;
	rt_sigrestore_t	rt_sa_restorer;
	k_rtsigset_t	rt_sa_mask;
} rt_sigaction_t;

typedef UserArmRegsEntry UserRegsEntry;

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__ARM

#define CORE_THREAD_ARCH_INFO(core) core->ti_arm

#define TI_SP(core) ((core)->ti_arm->gpregs->sp)

static inline void *decode_pointer(u64 v) { return (void*)(u32)v; }
static inline u64 encode_pointer(void *p) { return (u32)p; }

#endif /* __CR_ASM_TYPES_H__ */
