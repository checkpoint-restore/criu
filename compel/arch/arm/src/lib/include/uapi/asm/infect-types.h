#ifndef UAPI_COMPEL_ASM_TYPES_H__
#define UAPI_COMPEL_ASM_TYPES_H__

#include <stdint.h>
#include <sys/mman.h>

#define SIGMAX	   64
#define SIGMAX_OLD 31

/*
 * Copied from the Linux kernel header arch/arm/include/asm/ptrace.h
 *
 * A thread ARM CPU context
 */

typedef struct {
	long uregs[18];
} user_regs_struct_t;

#define __compel_arch_fetch_thread_area(tid, th) 0
#define compel_arch_fetch_thread_area(tctl)	 0
#define compel_arch_get_tls_task(ctl, tls)
#define compel_arch_get_tls_thread(tctl, tls)

typedef struct user_vfp user_fpregs_struct_t;

#define ARM_cpsr    uregs[16]
#define ARM_pc	    uregs[15]
#define ARM_lr	    uregs[14]
#define ARM_sp	    uregs[13]
#define ARM_ip	    uregs[12]
#define ARM_fp	    uregs[11]
#define ARM_r10	    uregs[10]
#define ARM_r9	    uregs[9]
#define ARM_r8	    uregs[8]
#define ARM_r7	    uregs[7]
#define ARM_r6	    uregs[6]
#define ARM_r5	    uregs[5]
#define ARM_r4	    uregs[4]
#define ARM_r3	    uregs[3]
#define ARM_r2	    uregs[2]
#define ARM_r1	    uregs[1]
#define ARM_r0	    uregs[0]
#define ARM_ORIG_r0 uregs[17]

/* Copied from arch/arm/include/asm/user.h */

struct user_vfp {
	unsigned long long fpregs[32];
	unsigned long fpscr;
};

struct user_vfp_exc {
	unsigned long fpexc;
	unsigned long fpinst;
	unsigned long fpinst2;
};

#define REG_RES(regs)	      ((regs).ARM_r0)
#define REG_IP(regs)	      ((regs).ARM_pc)
#define SET_REG_IP(regs, val) ((regs).ARM_pc = (val))
#define REG_SP(regs)	      ((regs).ARM_sp)
#define REG_SYSCALL_NR(regs)  ((regs).ARM_r7)

#define user_regs_native(pregs) true

#define ARCH_SI_TRAP TRAP_BRKPT

#define __NR(syscall, compat)   \
	({                      \
		(void)compat;   \
		__NR_##syscall; \
	})

#endif /* UAPI_COMPEL_ASM_TYPES_H__ */
