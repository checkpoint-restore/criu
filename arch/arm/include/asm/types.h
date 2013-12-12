#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include "protobuf/core.pb-c.h"

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
#define _NSIG_BPW	32

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

#define SA_RESTORER	0x04000000

typedef struct {
	rt_sighandler_t	rt_sa_handler;
	unsigned long	rt_sa_flags;
	rt_sigrestore_t	rt_sa_restorer;
	k_rtsigset_t	rt_sa_mask;
} rt_sigaction_t;

/*
 * Copied from the Linux kernel header arch/arm/include/asm/ptrace.h
 *
 * A thread ARM CPU context
 */

typedef struct {
        long uregs[18];
} user_regs_struct_t;

#define ARM_cpsr        uregs[16]
#define ARM_pc          uregs[15]
#define ARM_lr          uregs[14]
#define ARM_sp          uregs[13]
#define ARM_ip          uregs[12]
#define ARM_fp          uregs[11]
#define ARM_r10         uregs[10]
#define ARM_r9          uregs[9]
#define ARM_r8          uregs[8]
#define ARM_r7          uregs[7]
#define ARM_r6          uregs[6]
#define ARM_r5          uregs[5]
#define ARM_r4          uregs[4]
#define ARM_r3          uregs[3]
#define ARM_r2          uregs[2]
#define ARM_r1          uregs[1]
#define ARM_r0          uregs[0]
#define ARM_ORIG_r0     uregs[17]


/* Copied from arch/arm/include/asm/user.h */

struct user_vfp {
	unsigned long long fpregs[32];
	unsigned long fpscr;
};

struct user_vfp_exc {
        unsigned long   fpexc;
	unsigned long   fpinst;
	unsigned long   fpinst2;
};

#define ASSIGN_TYPED(a, b) do { a = (typeof(a))b; } while (0)
#define ASSIGN_MEMBER(a,b,m) do { ASSIGN_TYPED((a)->m, (b)->m); } while (0)

#ifndef PAGE_SIZE
# define PAGE_SIZE	4096
#endif

#ifndef PAGE_MASK
# define PAGE_MASK	(~(PAGE_SIZE - 1))
#endif

#define REG_RES(regs) ((regs).ARM_r0)
#define REG_IP(regs)  ((regs).ARM_pc)
#define REG_SYSCALL_NR(regs) ((regs).ARM_r7)

#define TASK_SIZE 0xbf000000

#define AT_VECTOR_SIZE 40

typedef UserArmRegsEntry UserRegsEntry;

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__ARM

#define CORE_THREAD_ARCH_INFO(core) core->ti_arm

#define TI_SP(core) ((core)->ti_arm->gpregs->sp)

typedef u32 auxv_t;

static inline void *decode_pointer(u64 v) { return (void*)(u32)v; }
static inline u64 encode_pointer(void *p) { return (u32)p; }

#endif /* __CR_ASM_TYPES_H__ */
