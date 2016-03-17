#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include "asm/types.h"
#include "images/core.pb-c.h"

/* Copied from the Linux kernel header arch/arm/include/asm/sigcontext.h */

struct rt_sigcontext {
	unsigned long trap_no;
	unsigned long error_code;
	unsigned long oldmask;
	unsigned long arm_r0;
	unsigned long arm_r1;
	unsigned long arm_r2;
	unsigned long arm_r3;
	unsigned long arm_r4;
	unsigned long arm_r5;
	unsigned long arm_r6;
	unsigned long arm_r7;
	unsigned long arm_r8;
	unsigned long arm_r9;
	unsigned long arm_r10;
	unsigned long arm_fp;
	unsigned long arm_ip;
	unsigned long arm_sp;
	unsigned long arm_lr;
	unsigned long arm_pc;
	unsigned long arm_cpsr;
	unsigned long fault_address;
};

/* Copied from the Linux kernel header arch/arm/include/asm/ucontext.h */

#define VFP_MAGIC               0x56465001
#define VFP_STORAGE_SIZE        sizeof(struct vfp_sigframe)

struct vfp_sigframe {
	unsigned long           magic;
	unsigned long           size;
	struct user_vfp         ufp;
	struct user_vfp_exc     ufp_exc;
};

typedef struct vfp_sigframe fpu_state_t;

struct aux_sigframe {
	/*
	struct crunch_sigframe  crunch;
        struct iwmmxt_sigframe  iwmmxt;
	*/

	struct vfp_sigframe     vfp;
	unsigned long           end_magic;
} __attribute__((__aligned__(8)));

#include "sigframe.h"

struct sigframe {
	struct rt_ucontext uc;
	unsigned long retcode[2];
};

struct rt_sigframe {
	struct rt_siginfo info;
	struct sigframe sig;
};


#define ARCH_RT_SIGRETURN(new_sp)					\
	asm volatile(							\
		     "mov %%sp, %0				    \n"	\
		     "mov %%r7,  #"__stringify(__NR_rt_sigreturn)"  \n" \
		     "svc #0					    \n"	\
		     :							\
		     : "r"(new_sp)					\
		     : "sp","memory")

#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,	\
			     thread_args, clone_restore_fn)		\
	asm volatile(							\
		     "clone_emul:				\n"	\
		     "ldr %%r1, %2				\n"	\
		     "sub %%r1, #16				\n"	\
		     "mov %%r0, %%%6				\n"	\
		     "str %%r0, [%%r1, #4]			\n"	\
		     "mov %%r0, %%%5				\n"	\
		     "str %%r0, [%%r1]				\n"	\
		     "mov %%r0, %%%1				\n"	\
		     "mov %%r2, %%%3				\n"	\
		     "mov %%r3, %%%4				\n"	\
		     "mov %%r7, #"__stringify(__NR_clone)"	\n"	\
		     "svc #0					\n"	\
									\
		     "cmp %%r0, #0				\n"	\
		     "beq thread_run				\n"	\
									\
		     "mov %%%0, %%r0				\n"	\
		     "b   clone_end				\n"	\
									\
		     "thread_run:				\n"	\
		     "pop { %%r1 }				\n"	\
		     "pop { %%r0 }				\n"	\
		     "bx  %%r1					\n"	\
									\
		     "clone_end:				\n"	\
		     : "=r"(ret)					\
		     : "r"(clone_flags),				\
		       "m"(new_sp),					\
		       "r"(&parent_tid),				\
		       "r"(&thread_args[i].pid),			\
		       "r"(clone_restore_fn),				\
		       "r"(&thread_args[i])				\
		     : "r0", "r1", "r2", "r3", "r7", "memory")

#define ARCH_FAIL_CORE_RESTORE					\
	asm volatile(						\
		     "mov %%sp, %0			    \n"	\
		     "mov %%r0, #0			    \n"	\
		     "bx  %%r0				    \n"	\
		     :						\
		     : "r"(ret)					\
		     : "memory")


#define RT_SIGFRAME_UC(rt_sigframe) (&rt_sigframe->sig.uc)
#define RT_SIGFRAME_REGIP(rt_sigframe) (rt_sigframe)->sig.uc.uc_mcontext.arm_ip
#define RT_SIGFRAME_HAS_FPU(rt_sigframe) 1
#define RT_SIGFRAME_FPU(rt_sigframe) ((struct aux_sigframe *)&sigframe->sig.uc.uc_regspace)->vfp

#define SIGFRAME_OFFSET 0


int restore_gpregs(struct rt_sigframe *f, UserArmRegsEntry *r);
int restore_nonsigframe_gpregs(UserArmRegsEntry *r);

static inline int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe, fpu_state_t *fpu_state) { return 0; }

static inline void restore_tls(tls_t *ptls) {
	asm (
	     "mov %%r7, #15  \n"
	     "lsl %%r7, #16  \n"
	     "mov %%r0, #5   \n"
	     "add %%r7, %%r0 \n"	/* r7 = 0xF005 */
	     "ldr %%r0, [%0] \n"
	     "svc #0         \n"
	     :
	     : "r"(ptls)
	     : "r0", "r7"
	     );
}

static inline int ptrace_set_breakpoint(pid_t pid, void *addr)
{
	return 0;
}

static inline int ptrace_flush_breakpoints(pid_t pid)
{
	return 0;
}

#endif
