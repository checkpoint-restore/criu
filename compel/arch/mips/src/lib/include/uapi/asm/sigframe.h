#ifndef UAPI_COMPEL_ASM_SIGFRAME_H__
#define UAPI_COMPEL_ASM_SIGFRAME_H__

#include <stdint.h>
#include <stdbool.h>

#include <compel/asm/fpu.h>
#include <compel/plugins/std/syscall-codes.h>

//#define SIGFRAME_MAX_OFFSET 8

/*
 *fixme: gysun
*/
#include <asm/types.h>
#define u32 __u32

/* sigcontext defined in /usr/include/asm/sigcontext.h*/
#define rt_sigcontext			sigcontext


//#include <bits/siginfo.h>
#include <signal.h>
#include <compel/sigframe-common.h>
//#include <sys/ucontext.h>
/* refer to linux-3.10/include/uapi/asm-generic/ucontext.h */
struct k_ucontext{
    unsigned long uc_flags;
    struct k_ucontext *uc_link;
    stack_t uc_stack;
    struct sigcontext uc_mcontext;
//    sigset_t uc_sigmask;
    k_rtsigset_t uc_sigmask;
};

/* Copy from the kernel source arch/mips/kernel/signal.c */
struct rt_sigframe {
	u32 rs_ass[4];		/* argument save space for o32 */
	u32 rs_pad[2];		/* Was: signal trampoline */
//struct siginfo rs_info;
        siginfo_t rs_info;
	struct k_ucontext rs_uc;
};


/*
 * XXX: move declarations to generic sigframe.h or sigframe-compat.h
 *      when (if) other architectures will support compatible C/R
 */

typedef uint32_t			compat_uptr_t;
typedef uint32_t			compat_size_t;

typedef struct compat_siginfo {
	int	si_signo;
	int	si_errno;
	int	si_code;
	int	_pad[128/sizeof(int) - 3];
} compat_siginfo_t;

typedef struct compat_sigaltstack {
	compat_uptr_t		ss_sp;
	int			ss_flags;
	compat_size_t		ss_size;
} compat_stack_t;

/*fixme: gysun*/
#define RT_SIGFRAME_UC(rt_sigframe)		(&rt_sigframe->rs_uc)
#define RT_SIGFRAME_UC_SIGMASK(rt_sigframe) 	((k_rtsigset_t *)(void *)&rt_sigframe->rs_uc.uc_sigmask)
#define RT_SIGFRAME_REGIP(rt_sigframe)	((long unsigned int)0x00)   
#define RT_SIGFRAME_FPU(rt_sigframe)		     
#define RT_SIGFRAME_HAS_FPU(rt_sigframe) 1


/*fixme: gysun*/
#define RT_SIGFRAME_OFFSET(rt_sigframe)	0

#define USER32_CS		0x23


/*fixme: gysun 汇编指令*/
#define ARCH_RT_SIGRETURN(new_sp, rt_sigframe)				\
	asm volatile(							\
		     "move $29, %0				    \n"	\
		     "li $2,  "__stringify(__NR_rt_sigreturn)"  \n" \
		     "syscall					    \n"	\
		     :							\
		     : "r"(new_sp)					\
		     : "$29","$2","memory")

int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe,
		struct rt_sigframe *rsigframe);

#define rt_sigframe_erase_sigset(sigframe)				\
	memset(&sigframe->rs_uc.uc_sigmask, 0, sizeof(k_rtsigset_t))
#define rt_sigframe_copy_sigset(sigframe, from)				\
	memcpy(&sigframe->rs_uc.uc_sigmask, from, sizeof(k_rtsigset_t))
#endif /* UAPI_COMPEL_ASM_SIGFRAME_H__ */
