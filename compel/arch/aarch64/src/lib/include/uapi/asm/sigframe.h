#ifndef UAPI_COMPEL_ASM_SIGFRAME_H__
#define UAPI_COMPEL_ASM_SIGFRAME_H__

#include <asm/sigcontext.h>
#include <sys/ucontext.h>

#include <stdint.h>

/* Copied from the kernel header arch/arm64/include/uapi/asm/sigcontext.h */

#define FPSIMD_MAGIC			0x46508001

typedef struct fpsimd_context		fpu_state_t;

struct aux_context {
	struct fpsimd_context		fpsimd;
	/* additional context to be added before "end" */
	struct _aarch64_ctx		end;
};

// XXX: the idetifier rt_sigcontext is expected to be struct by the CRIU code
#define rt_sigcontext			sigcontext

#include <compel/sigframe-common.h>

/* Copied from the kernel source arch/arm64/kernel/signal.c */

struct rt_sigframe {
	siginfo_t			info;
	struct ucontext			uc;
	uint64_t			fp;
	uint64_t			lr;
};

#define ARCH_RT_SIGRETURN(new_sp, rt_sigframe)					\
	asm volatile(								\
			"mov sp, %0					\n"	\
			"mov x8, #"__stringify(__NR_rt_sigreturn)"	\n"	\
			"svc #0						\n"	\
			:							\
			: "r"(new_sp)						\
			: "sp", "x8", "memory")

#define RT_SIGFRAME_UC(rt_sigframe)		(&rt_sigframe->uc)
#define RT_SIGFRAME_REGIP(rt_sigframe)		((long unsigned int)(rt_sigframe)->uc.uc_mcontext.pc)
#define RT_SIGFRAME_HAS_FPU(rt_sigframe)	(1)
#define RT_SIGFRAME_AUX_CONTEXT(rt_sigframe)	((struct aux_context*)&(rt_sigframe)->uc.uc_mcontext.__reserved)
#define RT_SIGFRAME_FPU(rt_sigframe)		(&RT_SIGFRAME_AUX_CONTEXT(rt_sigframe)->fpsimd)
#define RT_SIGFRAME_OFFSET(rt_sigframe)		0

#endif /* UAPI_COMPEL_ASM_SIGFRAME_H__ */
