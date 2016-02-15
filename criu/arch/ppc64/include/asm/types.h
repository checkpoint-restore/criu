#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>
#include "protobuf/core.pb-c.h"

#include "asm/page.h"
#include "asm/bitops.h"
#include "asm/int.h"

/*
 * Copied from kernel header include/uapi/asm-generic/signal-defs.h
 */
typedef void rt_signalfn_t(int, siginfo_t *, void *);
typedef rt_signalfn_t *rt_sighandler_t;

typedef void rt_restorefn_t(void);
typedef rt_restorefn_t *rt_sigrestore_t;

#define SIGMAX_OLD	31
#define SIGMAX		64

/*Copied from the Linux kernel arch/powerpc/include/uapi/asm/signal.h */
#define _KNSIG		64
#define _NSIG_BPW       64
#define _KNSIG_WORDS     (_KNSIG / _NSIG_BPW)

typedef struct {
        uint64_t sig[_KNSIG_WORDS];
} k_rtsigset_t;

static inline void ksigfillset(k_rtsigset_t *set)
{
        int i;
        for (i = 0; i < _KNSIG_WORDS; i++)
                set->sig[i] = (unsigned long)-1;
}

/* Copied from the Linux kernel arch/powerpc/include/uapi/asm/signal.h */
#define SA_RESTORER     0x04000000U

typedef struct {
        rt_sighandler_t rt_sa_handler;
        unsigned long rt_sa_flags;
        rt_sigrestore_t rt_sa_restorer;
        k_rtsigset_t rt_sa_mask;               /* mask last for extensibility */
} rt_sigaction_t;

/*
 * Copied from kernel header arch/powerpc/include/uapi/asm/ptrace.h
 */
typedef struct {
        unsigned long gpr[32];
        unsigned long nip;
        unsigned long msr;
        unsigned long orig_gpr3;        /* Used for restarting system calls */
        unsigned long ctr;
        unsigned long link;
        unsigned long xer;
        unsigned long ccr;
        unsigned long softe;            /* Soft enabled/disabled */
        unsigned long trap;             /* Reason for being here */
        /* N.B. for critical exceptions on 4xx, the dar and dsisr
           fields are overloaded to hold srr0 and srr1. */
        unsigned long dar;              /* Fault registers */
        unsigned long dsisr;            /* on 4xx/Book-E used for ESR */
        unsigned long result;           /* Result of a system call */
} user_regs_struct_t;

typedef UserPpc64RegsEntry UserRegsEntry;

#define CORE_ENTRY__MARCH	CORE_ENTRY__MARCH__PPC64

#define ASSIGN_TYPED(a, b) do { a = (typeof(a))b; } while (0)
#define ASSIGN_MEMBER(a,b,m) do { ASSIGN_TYPED((a)->m, (b)->m); } while (0)

#define REG_RES(regs)           ((u64)(regs).gpr[3])
#define REG_IP(regs)            ((u64)(regs).nip)
#define REG_SYSCALL_NR(regs)    ((u64)(regs).gpr[0])


#define CORE_THREAD_ARCH_INFO(core) core->ti_ppc64

/*
 * Copied from the following kernel header files :
 * 	include/linux/auxvec.h
 *	arch/powerpc/include/uapi/asm/auxvec.h
 *	include/linux/mm_types.h
 */
#define AT_VECTOR_SIZE_BASE 20
#define AT_VECTOR_SIZE_ARCH 6
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

typedef uint64_t auxv_t;

/* Not used but the structure parasite_dump_thread needs a tls_t field */
typedef uint64_t tls_t;

/*
 * Copied for the Linux kernel arch/powerpc/include/asm/processor.h
 *
 * NOTE: 32bit tasks are not supported.
 */
#define TASK_SIZE_USER64 (0x0000400000000000UL)
#define TASK_SIZE TASK_SIZE_USER64

static inline unsigned long task_size() { return TASK_SIZE; }

static inline void *decode_pointer(uint64_t v) { return (void*)v; }
static inline uint64_t encode_pointer(void *p) { return (uint64_t)p; }

#endif /* __CR_ASM_TYPES_H__ */
