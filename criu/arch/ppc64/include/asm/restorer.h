#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

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

#include "sigframe.h"
#define SIGFRAME_OFFSET 0

/* Copied from the Linux kernel header arch/powerpc/include/asm/ptrace.h */
#define USER_REDZONE_SIZE       512

/* Copied from the Linux kernel source file arch/powerpc/kernel/signal_64.c */
#define TRAMP_SIZE      	6

/*
 * ucontext defined in /usr/include/powerpc64le-linux-gnu/sys/ucontext.h
 */
struct rt_sigframe {
        /* sys_rt_sigreturn requires the ucontext be the first field */
        struct ucontext uc;
#if 1
	/*
	 * XXX: Assuming that transactional is turned on by default in
	 * most of the Linux distribution.
	 */
        struct ucontext uc_transact;
#endif
        unsigned long _unused[2];
        unsigned int tramp[TRAMP_SIZE];
        struct rt_siginfo *pinfo;
        void *puc;
        struct rt_siginfo info;
        /* New 64 bit little-endian ABI allows redzone of 512 bytes below sp */
        char abigap[USER_REDZONE_SIZE];
} __attribute__ ((aligned (16)));

#define ARCH_RT_SIGRETURN(new_sp)				\
        asm volatile(						\
		"mr 1, %0 \n"					\
		"li 0, "__stringify(__NR_rt_sigreturn)" \n"	\
		"sc \n"						\
		:						\
		: "r"(new_sp)					\
		: "1", "memory")

/*
 * Clone trampoline
 *
 * See glibc sysdeps/powerpc/powerpc64/sysdep.h for FRAME_MIN_SIZE defines
 */
#if _CALL_ELF != 2
#error Only supporting ABIv2.
#else
#define FRAME_MIN_SIZE_PARM     96
#endif
#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid, 	\
			     thread_args, clone_restore_fn)		\
	asm volatile( 							\
		"clone_emul:					\n"	\
		"/* Save fn, args, stack across syscall. */ 	\n"	\
		"mr	14, %5	/* clone_restore_fn in r14 */ 	\n"	\
		"mr	15, %6	/* &thread_args[i] in r15 */ 	\n"	\
		"mr	3, %1	/* clone_flags */ 		\n"	\
		"ld	4, %2	/* new_sp */ 			\n"	\
		"mr	5, %3	/* &parent_tid */ 		\n"	\
		"li	6, 0	/* tls = 0 ? */ 		\n"	\
		"mr	7, %4	/* &thread_args[i].pid */ 	\n"	\
		"li	0,"__stringify(__NR_clone)" 		\n"	\
		"sc 						\n"	\
		"/* Check for child process.  */		\n"	\
		"cmpdi   cr1,3,0 				\n"	\
		"crandc  cr1*4+eq,cr1*4+eq,cr0*4+so 		\n"	\
		"bne-    cr1,clone_end 				\n"	\
		"/* child */					\n"	\
		"addi 14, 14, 8 /* jump over r2 fixup */	\n"	\
		"mtctr	14					\n"	\
		"mr	3,15 					\n"	\
		"bctr 						\n"	\
		"clone_end:					\n"	\
		"mr	%0,3 \n"					\
		: "=r"(ret)			/* %0 */		\
		: "r"(clone_flags),		/* %1 */		\
		  "m"(new_sp),			/* %2 */		\
		  "r"(&parent_tid),		/* %3 */		\
		  "r"(&thread_args[i].pid),	/* %4 */		\
		  "r"(clone_restore_fn),	/* %5 */		\
		  "r"(&thread_args[i])		/* %6 */		\
		: "memory","0","3","4","5","6","7","14","15")

#define RT_SIGFRAME_UC(rt_sigframe) (&(rt_sigframe)->uc)
#define RT_SIGFRAME_REGIP(rt_sigframe) ((long unsigned int)(rt_sigframe)->uc.uc_mcontext.gp_regs[PT_NIP])
#define RT_SIGFRAME_HAS_FPU(rt_sigframe) (1)
#define RT_SIGFRAME_FPU(rt_sigframe) ((rt_sigframe)->uc.uc_mcontext)

int restore_gpregs(struct rt_sigframe *f, UserPpc64RegsEntry *r);
int restore_nonsigframe_gpregs(UserPpc64RegsEntry *r);

/* Nothing to do, TLS is accessed through r13 */
static inline void restore_tls(tls_t *ptls) { (void)ptls; }

static inline int ptrace_set_breakpoint(pid_t pid, void *addr)
{
        return 0;
}

static inline int ptrace_flush_breakpoints(pid_t pid)
{
        return 0;
}

int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe,
			     mcontext_t *sigcontext);

/*
 * Defined in arch/ppc64/syscall-common-ppc64.S
 */
unsigned long sys_shmat(int shmid, const void *shmaddr, int shmflg);

#endif /*__CR_ASM_RESTORER_H__*/
