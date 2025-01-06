#ifndef UAPI_COMPEL_ASM_SIGFRAME_H__
#define UAPI_COMPEL_ASM_SIGFRAME_H__

#include <asm/sigcontext.h>
#include <sys/ucontext.h>

#include <stdint.h>

/* Copied from the kernel header arch/arm64/include/uapi/asm/sigcontext.h */

#define FPSIMD_MAGIC 0x46508001

typedef struct fpsimd_context fpu_state_t;

struct aux_context {
	struct fpsimd_context fpsimd;
	/* additional context to be added before "end" */
	struct _aarch64_ctx end;
};

// XXX: the identifier rt_sigcontext is expected to be struct by the CRIU code
#define rt_sigcontext sigcontext

#include <compel/sigframe-common.h>

/* Copied from the kernel source arch/arm64/kernel/signal.c */

struct rt_sigframe {
	siginfo_t info;
	ucontext_t uc;
	uint64_t fp;
	uint64_t lr;
};

/* clang-format off */
#define ARCH_RT_SIGRETURN(new_sp, rt_sigframe)					\
	asm volatile(								\
			"mov sp, %0					\n"	\
			"mov x8, #"__stringify(__NR_rt_sigreturn)"	\n"	\
			"svc #0						\n"	\
			:							\
			: "r"(new_sp)						\
			: "x8", "memory")
/* clang-format on */

/* cr_sigcontext is copied from arch/arm64/include/uapi/asm/sigcontext.h */
struct cr_sigcontext {
	__u64 fault_address;
	/* AArch64 registers */
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
	/* 4K reserved for FP/SIMD state and future expansion */
	__u8 __reserved[4096] __attribute__((__aligned__(16)));
};

#define RT_SIGFRAME_UC(rt_sigframe)	     (&rt_sigframe->uc)
#define RT_SIGFRAME_REGIP(rt_sigframe)	     ((long unsigned int)(rt_sigframe)->uc.uc_mcontext.pc)
#define RT_SIGFRAME_HAS_FPU(rt_sigframe)     (1)
#define RT_SIGFRAME_SIGCONTEXT(rt_sigframe)  ((struct cr_sigcontext *)&(rt_sigframe)->uc.uc_mcontext)
#define RT_SIGFRAME_AUX_CONTEXT(rt_sigframe) ((struct aux_context *)&(RT_SIGFRAME_SIGCONTEXT(rt_sigframe)->__reserved))
#define RT_SIGFRAME_FPU(rt_sigframe)	     (&RT_SIGFRAME_AUX_CONTEXT(rt_sigframe)->fpsimd)
#define RT_SIGFRAME_OFFSET(rt_sigframe)	     0

#define rt_sigframe_erase_sigset(sigframe)	memset(&sigframe->uc.uc_sigmask, 0, sizeof(k_rtsigset_t))
#define rt_sigframe_copy_sigset(sigframe, from) memcpy(&sigframe->uc.uc_sigmask, from, sizeof(k_rtsigset_t))

#endif /* UAPI_COMPEL_ASM_SIGFRAME_H__ */
