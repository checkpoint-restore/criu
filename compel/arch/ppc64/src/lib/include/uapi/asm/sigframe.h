#ifndef UAPI_COMPEL_ASM_SIGFRAME_H__
#define UAPI_COMPEL_ASM_SIGFRAME_H__

#include <asm/ptrace.h>
#include <asm/elf.h>
#include <asm/types.h>

/*
 * sigcontext structure defined in file
 *	/usr/include/powerpc64le-linux-gnu/bits/sigcontext.h,
 * included from /usr/include/signal.h
 *
 * Kernel definition can be found in arch/powerpc/include/uapi/asm/sigcontext.h
 */
#include <signal.h>

// XXX: the idetifier rt_sigcontext is expected to be struct by the CRIU code
#define rt_sigcontext sigcontext

#include <compel/sigframe-common.h>

#define RT_SIGFRAME_OFFSET(rt_sigframe)	0

/* Copied from the Linux kernel header arch/powerpc/include/asm/ptrace.h */
#define USER_REDZONE_SIZE		512

/* Copied from the Linux kernel source file arch/powerpc/kernel/signal_64.c */
#define TRAMP_SIZE			6

/*
 * ucontext_t defined in /usr/include/powerpc64le-linux-gnu/sys/ucontext.h
 */
struct rt_sigframe {
        /* sys_rt_sigreturn requires the ucontext be the first field */
        ucontext_t			uc;
        ucontext_t			uc_transact; /* Transactional state	 */
        unsigned long			_unused[2];
        unsigned int			tramp[TRAMP_SIZE];
        struct rt_siginfo		*pinfo;
        void				*puc;
        struct rt_siginfo		info;
        /* New 64 bit little-endian ABI allows redzone of 512 bytes below sp */
        char				abigap[USER_REDZONE_SIZE];
} __attribute__((aligned(16)));

#define ARCH_RT_SIGRETURN(new_sp, rt_sigframe)			\
        asm volatile(						\
		"mr 1, %0 \n"					\
		"li 0, "__stringify(__NR_rt_sigreturn)" \n"	\
		"sc \n"						\
		:						\
		: "r"(new_sp)					\
		: "1", "memory")

#if _CALL_ELF != 2
# error Only supporting ABIv2.
#else
# define FRAME_MIN_SIZE_PARM		96
#endif

#define RT_SIGFRAME_UC(rt_sigframe)		(&(rt_sigframe)->uc)
#define RT_SIGFRAME_REGIP(rt_sigframe)		((long unsigned int)(rt_sigframe)->uc.uc_mcontext.gp_regs[PT_NIP])
#define RT_SIGFRAME_HAS_FPU(rt_sigframe)	(1)
#define RT_SIGFRAME_FPU(rt_sigframe)		(&(rt_sigframe)->uc.uc_mcontext)

#define rt_sigframe_erase_sigset(sigframe)				\
	memset(&sigframe->uc.uc_sigmask, 0, sizeof(k_rtsigset_t))
#define rt_sigframe_copy_sigset(sigframe, from)				\
	memcpy(&sigframe->uc.uc_sigmask, from, sizeof(k_rtsigset_t))

#define MSR_TMA (1UL<<34)	/* bit 29 Trans Mem state: Transactional */
#define MSR_TMS (1UL<<33)	/* bit 30 Trans Mem state: Suspended */
#define MSR_TM  (1UL<<32)	/* bit 31 Trans Mem Available */
#define MSR_VEC (1UL<<25)
#define MSR_VSX (1UL<<23)

#define MSR_TM_ACTIVE(x) ((((x) & MSR_TM) && ((x)&(MSR_TMA|MSR_TMS))) != 0)

#endif /* UAPI_COMPEL_ASM_SIGFRAME_H__ */
