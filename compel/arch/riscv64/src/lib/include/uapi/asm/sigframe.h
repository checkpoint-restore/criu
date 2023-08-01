#ifndef UAPI_COMPEL_ASM_SIGFRAME_H__
#define UAPI_COMPEL_ASM_SIGFRAME_H__

#include <sys/ucontext.h>

#include <stdint.h>

#include <signal.h>

/* Copied from the kernel header arch/riscv/include/uapi/asm/sigcontext.h */
/*
 * Signal context structure
 *
 * This contains the context saved before a signal handler is invoked;
 * it is restored by sys_sigreturn / sys_rt_sigreturn.
 */
// struct sigcontext {
// 	struct user_regs_struct sc_regs;
// 	union __riscv_fp_state sc_fpregs;
// 	/*
// 	 * 4K + 128 reserved for vector state and future expansion.
// 	 * This space is enough to store the vector context whose VLENB
// 	 * is less or equal to 128.
// 	 * (The size of the vector context is 4144 byte as VLENB is 128)
// 	 */
// 	__u8 __reserved[4224] __attribute__((__aligned__(16)));
// };

#define rt_sigcontext sigcontext

#include <compel/sigframe-common.h>

/* Copied from the kernel source arch/riscv/kernel/signal.c */
struct rt_sigframe {
	siginfo_t info;
	ucontext_t uc; //ucontext_t structure holds the user context, e.g., the signal mask, GP regs
};

/*
	generates inline assembly code for triggering the rt_sigreturn system call.
	used to return from a signal handler back to the normal execution flow of the process.
*/
/* clang-format off */
#define ARCH_RT_SIGRETURN(new_sp, rt_sigframe)					\
	asm volatile(								\
			"mv sp, %0\n"	\
			"li a7,  "__stringify(__NR_rt_sigreturn)" \n"     \
			"ecall\n"	\
			:							\
			: "r"(new_sp)						\
			: "a7", "memory")
/* clang-format on */

#define RT_SIGFRAME_UC(rt_sigframe)	 (&rt_sigframe->uc)
#define RT_SIGFRAME_REGIP(rt_sigframe)	 ((long unsigned int)(rt_sigframe)->uc.uc_mcontext.__gregs[REG_PC])
#define RT_SIGFRAME_HAS_FPU(rt_sigframe) 1
#define RT_SIGFRAME_OFFSET(rt_sigframe)	 0

// #define RT_SIGFRAME_SIGCONTEXT(rt_sigframe)  ((struct cr_sigcontext *)&(rt_sigframe)->uc.uc_mcontext)
// #define RT_SIGFRAME_AUX_CONTEXT(rt_sigframe) ((struct sigcontext *)&(RT_SIGFRAME_SIGCONTEXT(rt_sigframe)->__reserved))
// #define RT_SIGFRAME_FPU(rt_sigframe)	     (&RT_SIGFRAME_AUX_CONTEXT(rt_sigframe)->fpsimd)

#define rt_sigframe_erase_sigset(sigframe) \
	memset(&sigframe->uc.uc_sigmask, 0, sizeof(k_rtsigset_t)) // erase the signal mask
#define rt_sigframe_copy_sigset(sigframe, from) \
	memcpy(&sigframe->uc.uc_sigmask, from, sizeof(k_rtsigset_t)) // copy the signal mask

#endif /* UAPI_COMPEL_ASM_SIGFRAME_H__ */