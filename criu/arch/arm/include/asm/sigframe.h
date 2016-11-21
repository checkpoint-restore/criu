#ifndef UAPI_COMPEL_ASM_SIGFRAME_H__
#define UAPI_COMPEL_ASM_SIGFRAME_H__

/* Copied from the Linux kernel header arch/arm/include/asm/sigcontext.h */

struct rt_sigcontext {
	unsigned long		trap_no;
	unsigned long		error_code;
	unsigned long		oldmask;
	unsigned long		arm_r0;
	unsigned long		arm_r1;
	unsigned long		arm_r2;
	unsigned long		arm_r3;
	unsigned long		arm_r4;
	unsigned long		arm_r5;
	unsigned long		arm_r6;
	unsigned long		arm_r7;
	unsigned long		arm_r8;
	unsigned long		arm_r9;
	unsigned long		arm_r10;
	unsigned long		arm_fp;
	unsigned long		arm_ip;
	unsigned long		arm_sp;
	unsigned long		arm_lr;
	unsigned long		arm_pc;
	unsigned long		arm_cpsr;
	unsigned long		fault_address;
};

/* Copied from the Linux kernel header arch/arm/include/asm/ucontext.h */

#define VFP_MAGIC		0x56465001
#define VFP_STORAGE_SIZE	sizeof(struct vfp_sigframe)

struct vfp_sigframe {
	unsigned long		magic;
	unsigned long		size;
	struct user_vfp		ufp;
	struct user_vfp_exc	ufp_exc;
};

typedef struct vfp_sigframe	fpu_state_t;

struct aux_sigframe {
	/*
	struct crunch_sigframe  crunch;
	struct iwmmxt_sigframe  iwmmxt;
	*/

	struct vfp_sigframe	vfp;
	unsigned long		end_magic;
} __attribute__((aligned(8)));

#include "sigframe-common.h"

struct sigframe {
	struct rt_ucontext	uc;
	unsigned long		retcode[2];
};

struct rt_sigframe {
	struct rt_siginfo	info;
	struct sigframe		sig;
};


#define ARCH_RT_SIGRETURN(new_sp)					\
	asm volatile(							\
		     "mov sp, %0				    \n"	\
		     "mov r7,  #"__stringify(__NR_rt_sigreturn)"  \n" \
		     "svc #0					    \n"	\
		     :							\
		     : "r"(new_sp)					\
		     : "sp","memory")

#define RT_SIGFRAME_UC(rt_sigframe)		(&rt_sigframe->sig.uc)
#define RT_SIGFRAME_REGIP(rt_sigframe)		(rt_sigframe)->sig.uc.uc_mcontext.arm_ip
#define RT_SIGFRAME_HAS_FPU(rt_sigframe)	1
#define RT_SIGFRAME_AUX_SIGFRAME(rt_sigframe)	((struct aux_sigframe *)&(rt_sigframe)->sig.uc.uc_regspace)
#define RT_SIGFRAME_FPU(rt_sigframe)		(&RT_SIGFRAME_AUX_SIGFRAME(rt_sigframe)->vfp)
#define RT_SIGFRAME_OFFSET(rt_sigframe)		0

#endif /* UAPI_COMPEL_ASM_SIGFRAME_H__ */
