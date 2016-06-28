#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include <asm/sigcontext.h>
#include <sys/ucontext.h>

#include "asm/types.h"
#include "images/core.pb-c.h"

/* Copied from the kernel header arch/arm64/include/uapi/asm/sigcontext.h */

#define FPSIMD_MAGIC    0x46508001

typedef struct fpsimd_context fpu_state_t;


struct aux_context {
	struct fpsimd_context fpsimd;
	/* additional context to be added before "end" */
	struct _aarch64_ctx end;
};


// XXX: the idetifier rt_sigcontext is expected to be struct by the CRIU code
#define rt_sigcontext sigcontext


#include "sigframe.h"


/* Copied from the kernel source arch/arm64/kernel/signal.c */

struct rt_sigframe {
	siginfo_t info;
	struct ucontext uc;
	u64 fp;
	u64 lr;
};


#define ARCH_RT_SIGRETURN(new_sp)						\
	asm volatile(								\
			"mov sp, %0					\n"	\
			"mov x8, #"__stringify(__NR_rt_sigreturn)"	\n"	\
			"svc #0						\n"	\
			:							\
			: "r"(new_sp)						\
			: "sp", "x8", "memory")

#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,		\
			     thread_args, clone_restore_fn)			\
	asm volatile(								\
			"clone_emul:					\n"	\
			"ldr x1, %2					\n"	\
			"and x1, x1, #~15				\n"	\
			"sub x1, x1, #16				\n"	\
			"stp %5, %6, [x1]				\n"	\
			"mov x0, %1					\n"	\
			"mov x2, %3					\n"	\
			"mov x3, %4					\n"	\
			"mov x8, #"__stringify(__NR_clone)"		\n"	\
			"svc #0						\n"	\
										\
			"cbz x0, thread_run				\n"	\
										\
			"mov %0, x0					\n"	\
			"b   clone_end					\n"	\
										\
			"thread_run:					\n"	\
			"ldp x1, x0, [sp]				\n"	\
			"br  x1						\n"	\
										\
			"clone_end:					\n"	\
			: "=r"(ret)						\
			: "r"(clone_flags),					\
			  "m"(new_sp),						\
			  "r"(&parent_tid),					\
			  "r"(&thread_args[i].pid),				\
			  "r"(clone_restore_fn),				\
			  "r"(&thread_args[i])					\
			: "x0", "x1", "x2", "x3", "x8", "memory")

#define ARCH_FAIL_CORE_RESTORE					\
	asm volatile(						\
			"mov sp, %0			\n"	\
			"mov x0, #0			\n"	\
			"b   x0				\n"	\
			:					\
			: "r"(ret)				\
			: "sp", "x0", "memory")


#define RT_SIGFRAME_UC(rt_sigframe) (&rt_sigframe->uc)
#define RT_SIGFRAME_REGIP(rt_sigframe) ((long unsigned int)(rt_sigframe)->uc.uc_mcontext.pc)
#define RT_SIGFRAME_HAS_FPU(rt_sigframe) (1)
#define RT_SIGFRAME_AUX_CONTEXT(rt_sigframe)				\
	((struct aux_context*)&(rt_sigframe)->uc.uc_mcontext.__reserved)
#define RT_SIGFRAME_FPU(rt_sigframe)					\
	(&RT_SIGFRAME_AUX_CONTEXT(rt_sigframe)->fpsimd)
#define RT_SIGFRAME_OFFSET(rt_sigframe) 0


int restore_gpregs(struct rt_sigframe *f, UserAarch64RegsEntry *r);
int restore_nonsigframe_gpregs(UserAarch64RegsEntry *r);

static inline int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe,
		struct rt_sigframe *rsigframe)
{
	return 0;
}

static inline void restore_tls(tls_t *ptls)
{
	asm("msr tpidr_el0, %0" : : "r" (*ptls));
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
