#ifndef UAPI_COMPEL_ASM_SIGFRAME_H__
#define UAPI_COMPEL_ASM_SIGFRAME_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include <compel/asm/fpu.h>
#include <compel/plugins/std/syscall-codes.h>

#include <asm/types.h>

#define rt_sigcontext sigcontext
/* sigcontext defined in usr/include/uapi/asm/sigcontext.h*/
#include <compel/sigframe-common.h>
typedef __u32 u32;

typedef struct sigcontext_t {
	__u64 pc;
	__u64 regs[32];
	__u32 flags;
	__u64 extcontext[0] __attribute__((__aligned__(16)));
} sigcontext_t;

typedef struct context_info_t {
	__u32 magic;
	__u32 size;
	__u64 padding;
} context_info_t;

#define FPU_CTX_MAGIC 0x46505501
#define FPU_CTX_ALIGN 8
typedef struct fpu_context_t {
	__u64 regs[32];
	__u64 fcc;
	__u64 fcsr;
} fpu_context_t;

typedef struct ucontext {
	unsigned long uc_flags;
	struct ucontext *uc_link;
	stack_t uc_stack;
	sigset_t uc_sigmask;
	__u8 __unused[1024 / 8 - sizeof(sigset_t)];
	sigcontext_t uc_mcontext;
} ucontext;

/* Copy from the kernel source arch/loongarch/kernel/signal.c */
struct rt_sigframe {
	rt_siginfo_t rs_info;
	ucontext rs_uc;
};

#define RT_SIGFRAME_UC(rt_sigframe)	 (&(rt_sigframe->rs_uc))
#define RT_SIGFRAME_SIGMASK(rt_sigframe) ((k_rtsigset_t *)&RT_SIGFRAME_UC(rt_sigframe)->uc_sigmask)
#define RT_SIGFRAME_SIGCTX(rt_sigframe)	 (&(RT_SIGFRAME_UC(rt_sigframe)->uc_mcontext))
#define RT_SIGFRAME_REGIP(rt_sigframe)	 ((long unsigned int)(RT_SIGFRAME_SIGCTX(rt_sigframe)->pc))
#define RT_SIGFRAME_HAS_FPU(rt_sigframe) (1)

#define RT_SIGFRAME_FPU(rt_sigframe)                                                                 \
	({                                                                                           \
		context_info_t *ctx = (context_info_t *)RT_SIGFRAME_SIGCTX(rt_sigframe)->extcontext; \
		ctx->magic = FPU_CTX_MAGIC;                                                          \
		ctx->size = sizeof(context_info_t) + sizeof(fpu_context_t);                          \
		(fpu_context_t *)((char *)ctx + sizeof(context_info_t));                             \
	})

#define RT_SIGFRAME_OFFSET(rt_sigframe) 0

/* clang-format off */
#define ARCH_RT_SIGRETURN(new_sp, rt_sigframe)  \
    asm volatile(                               \
            "addi.d $sp, %0, 0 \n"              \
            "addi.d $a7, $zero, "__stringify(__NR_rt_sigreturn)"    \n" \
            "syscall   0"                       \
            :                                   \
            :"r"(new_sp)                        \
            : "$a7", "memory")
/* clang-format on */

int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe);

#define rt_sigframe_erase_sigset(sigframe)	memset(RT_SIGFRAME_SIGMASK(sigframe), 0, sizeof(k_rtsigset_t))
#define rt_sigframe_copy_sigset(sigframe, from) memcpy(RT_SIGFRAME_SIGMASK(sigframe), from, sizeof(k_rtsigset_t))

#endif /* UAPI_COMPEL_ASM_SIGFRAME_H__ */
