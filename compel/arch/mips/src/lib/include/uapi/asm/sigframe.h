#ifndef UAPI_COMPEL_ASM_SIGFRAME_H__
#define UAPI_COMPEL_ASM_SIGFRAME_H__

#include <stdint.h>
#include <stdbool.h>

#include <compel/asm/fpu.h>
#include <compel/plugins/std/syscall-codes.h>

#include <asm/types.h>
#define u32 __u32

/* sigcontext defined in /usr/include/asm/sigcontext.h*/
#define rt_sigcontext sigcontext

#include <compel/sigframe-common.h>

/* refer to linux-3.10/include/uapi/asm-generic/ucontext.h */
struct k_ucontext {
	unsigned long uc_flags;
	struct k_ucontext *uc_link;
	stack_t uc_stack;
	struct sigcontext uc_mcontext;
	k_rtsigset_t uc_sigmask;
};

/* Copy from the kernel source arch/mips/kernel/signal.c */
struct rt_sigframe {
	u32 rs_ass[4]; /* argument save space for o32 */
	u32 rs_pad[2]; /* Was: signal trampoline */
	siginfo_t rs_info;
	struct k_ucontext rs_uc;
};

#define RT_SIGFRAME_UC(rt_sigframe)	    (&rt_sigframe->rs_uc)
#define RT_SIGFRAME_UC_SIGMASK(rt_sigframe) ((k_rtsigset_t *)(void *)&rt_sigframe->rs_uc.uc_sigmask)
#define RT_SIGFRAME_REGIP(rt_sigframe)	    ((long unsigned int)0x00)
#define RT_SIGFRAME_FPU(rt_sigframe)
#define RT_SIGFRAME_HAS_FPU(rt_sigframe) 1

#define RT_SIGFRAME_OFFSET(rt_sigframe) 0

/* clang-format off */
#define ARCH_RT_SIGRETURN(new_sp, rt_sigframe)			\
	asm volatile(						\
	"move $29, %0					\n"	\
	"li $2,  "__stringify(__NR_rt_sigreturn)"	\n"	\
	"syscall					\n"	\
	:							\
	: "r"(new_sp)						\
	: "$2","memory")
/* clang-format on */

int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe);

#define rt_sigframe_erase_sigset(sigframe)	memset(&sigframe->rs_uc.uc_sigmask, 0, sizeof(k_rtsigset_t))
#define rt_sigframe_copy_sigset(sigframe, from) memcpy(&sigframe->rs_uc.uc_sigmask, from, sizeof(k_rtsigset_t))
#endif /* UAPI_COMPEL_ASM_SIGFRAME_H__ */
