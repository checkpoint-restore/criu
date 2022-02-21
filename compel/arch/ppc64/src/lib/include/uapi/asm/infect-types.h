#ifndef UAPI_COMPEL_ASM_TYPES_H__
#define UAPI_COMPEL_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>
#include <stdint.h>

#define SIGMAX_OLD 31
#define SIGMAX	   64

/*
 * Copied from kernel header arch/powerpc/include/uapi/asm/ptrace.h
 */
typedef struct {
	unsigned long gpr[32];
	unsigned long nip;
	unsigned long msr;
	unsigned long orig_gpr3; /* Used for restarting system calls */
	unsigned long ctr;
	unsigned long link;
	unsigned long xer;
	unsigned long ccr;
	unsigned long softe; /* Soft enabled/disabled */
	unsigned long trap;  /* Reason for being here */
	/*
	 * N.B. for critical exceptions on 4xx, the dar and dsisr
	 * fields are overloaded to hold srr0 and srr1.
	 */
	unsigned long dar;    /* Fault registers */
	unsigned long dsisr;  /* on 4xx/Book-E used for ESR */
	unsigned long result; /* Result of a system call */
} user_regs_struct_t;

#define NVSXREG 32

#define USER_FPREGS_FL_FP      0x00001
#define USER_FPREGS_FL_ALTIVEC 0x00002
#define USER_FPREGS_FL_VSX     0x00004
#define USER_FPREGS_FL_TM      0x00010

#ifndef NT_PPC_TM_SPR
#define NT_PPC_TM_CGPR 0x108 /* TM checkpointed GPR Registers */
#define NT_PPC_TM_CFPR 0x109 /* TM checkpointed FPR Registers */
#define NT_PPC_TM_CVMX 0x10a /* TM checkpointed VMX Registers */
#define NT_PPC_TM_CVSX 0x10b /* TM checkpointed VSX Registers */
#define NT_PPC_TM_SPR  0x10c /* TM Special Purpose Registers */
#endif

#define MSR_TMA (1UL << 34) /* bit 29 Trans Mem state: Transactional */
#define MSR_TMS (1UL << 33) /* bit 30 Trans Mem state: Suspended */
#define MSR_TM	(1UL << 32) /* bit 31 Trans Mem Available */
#define MSR_VEC (1UL << 25)
#define MSR_VSX (1UL << 23)

#define MSR_TM_ACTIVE(x) ((((x)&MSR_TM) && ((x) & (MSR_TMA | MSR_TMS))) != 0)

typedef struct {
	uint64_t fpregs[NFPREG];
	__vector128 vrregs[NVRREG];
	uint64_t vsxregs[NVSXREG];

	int flags;
	struct tm_regs {
		int flags;
		struct {
			uint64_t tfhar, texasr, tfiar;
		} tm_spr_regs;
		user_regs_struct_t regs;
		uint64_t fpregs[NFPREG];
		__vector128 vrregs[NVRREG];
		uint64_t vsxregs[NVSXREG];
	} tm;
} user_fpregs_struct_t;

#define REG_RES(regs)	      ((uint64_t)(regs).gpr[3])
#define REG_IP(regs)	      ((uint64_t)(regs).nip)
#define SET_REG_IP(regs, val) ((regs).nip = (val))
#define REG_SP(regs)	      ((uint64_t)(regs).gpr[1])
#define REG_SYSCALL_NR(regs)  ((uint64_t)(regs).gpr[0])

#define user_regs_native(pregs) true

#define ARCH_SI_TRAP TRAP_BRKPT

#define __NR(syscall, compat)   \
	({                      \
		(void)compat;   \
		__NR_##syscall; \
	})

#define __compel_arch_fetch_thread_area(tid, th) 0
#define compel_arch_fetch_thread_area(tctl)	 0
#define compel_arch_get_tls_task(ctl, tls)
#define compel_arch_get_tls_thread(tctl, tls)

#endif /* UAPI_COMPEL_ASM_TYPES_H__ */
