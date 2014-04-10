#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>
#include "protobuf/core.pb-c.h"

#include "asm-generic/page.h"
#include "asm/bitops.h"
#include "asm/int.h"


#define SIGMAX			64
#define SIGMAX_OLD		31

#define MAJOR(dev)		((dev)>>8)
#define MINOR(dev)		((dev) & 0xff)

typedef void rt_signalfn_t(int, siginfo_t *, void *);
typedef rt_signalfn_t *rt_sighandler_t;

typedef void rt_restorefn_t(void);
typedef rt_restorefn_t *rt_sigrestore_t;

#define _KNSIG		64
#define _NSIG_BPW	64

#define _KNSIG_WORDS	(_KNSIG / _NSIG_BPW)

typedef struct {
	unsigned long sig[_KNSIG_WORDS];
} k_rtsigset_t;

static inline void ksigfillset(k_rtsigset_t *set)
{
	int i;
	for (i = 0; i < _KNSIG_WORDS; i++)
		set->sig[i] = (unsigned long)-1;
}

#define SA_RESTORER	0x00000000

typedef struct {
	rt_sighandler_t	rt_sa_handler;
	unsigned long	rt_sa_flags;
	rt_sigrestore_t	rt_sa_restorer;
	k_rtsigset_t	rt_sa_mask;
} rt_sigaction_t;

/*
 * Copied from the Linux kernel header arch/arm64/include/uapi/asm/ptrace.h
 *
 * A thread ARM CPU context
 */

typedef struct user_pt_regs user_regs_struct_t;


#define ASSIGN_TYPED(a, b) do { a = (typeof(a))b; } while (0)
#define ASSIGN_MEMBER(a,b,m) do { ASSIGN_TYPED((a)->m, (b)->m); } while (0)

#define REG_RES(regs)		((u64)(regs).regs[0])
#define REG_IP(regs)		((u64)(regs).pc)
#define REG_SYSCALL_NR(regs)	((u64)(regs).regs[8])

// Copied from the Linux kernel arch/arm64/include/asm/memory.h
// FIXME: what about a 32bit task?

#define TASK_SIZE (1ULL << 39)

#define AT_VECTOR_SIZE 40

typedef UserAarch64RegsEntry UserRegsEntry;

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__AARCH64

#define CORE_THREAD_ARCH_INFO(core) core->ti_aarch64

#define TI_SP(core) ((core)->ti_aarch64->gpregs->sp)

typedef uint64_t auxv_t;
typedef uint64_t tls_t;

static inline void *decode_pointer(uint64_t v) { return (void*)v; }
static inline uint64_t encode_pointer(void *p) { return (uint64_t)p; }

#endif /* __CR_ASM_TYPES_H__ */
