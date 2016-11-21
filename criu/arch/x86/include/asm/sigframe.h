#ifndef UAPI_COMPEL_ASM_SIGFRAME_H__
#define UAPI_COMPEL_ASM_SIGFRAME_H__

#include <stdint.h>
#include <stdbool.h>

#include "asm/fpu.h"

#define SIGFRAME_MAX_OFFSET 8

struct rt_sigcontext {
	unsigned long			r8;
	unsigned long			r9;
	unsigned long			r10;
	unsigned long			r11;
	unsigned long			r12;
	unsigned long			r13;
	unsigned long			r14;
	unsigned long			r15;
	unsigned long			rdi;
	unsigned long			rsi;
	unsigned long			rbp;
	unsigned long			rbx;
	unsigned long			rdx;
	unsigned long			rax;
	unsigned long			rcx;
	unsigned long			rsp;
	unsigned long			rip;
	unsigned long			eflags;
	unsigned short			cs;
	unsigned short			gs;
	unsigned short			fs;
	unsigned short			ss;
	unsigned long			err;
	unsigned long			trapno;
	unsigned long			oldmask;
	unsigned long			cr2;
	void				*fpstate;
	unsigned long			reserved1[8];
};

#include "sigframe-common.h"

struct rt_sigframe {
	char			*pretcode;
	struct rt_ucontext	uc;
	struct rt_siginfo	info;

	fpu_state_t		fpu_state;
};

#define RT_SIGFRAME_UC(rt_sigframe) (&rt_sigframe->uc)
#define RT_SIGFRAME_REGIP(rt_sigframe) (rt_sigframe)->uc.uc_mcontext.rip
#define RT_SIGFRAME_FPU(rt_sigframe) (&(rt_sigframe)->fpu_state)
#define RT_SIGFRAME_HAS_FPU(rt_sigframe) (RT_SIGFRAME_FPU(rt_sigframe)->has_fpu)

#define RT_SIGFRAME_OFFSET(rt_sigframe) 8

#ifdef CONFIG_X86_64
#define ARCH_RT_SIGRETURN(new_sp)					\
	asm volatile(							\
		     "movq %0, %%rax				    \n"	\
		     "movq %%rax, %%rsp				    \n"	\
		     "movl $"__stringify(__NR_rt_sigreturn)", %%eax \n" \
		     "syscall					    \n"	\
		     :							\
		     : "r"(new_sp)					\
		     : "rax","rsp","memory")
#else /* CONFIG_X86_64 */
#define ARCH_RT_SIGRETURN(new_sp)					\
	asm volatile(							\
		     "movl %0, %%eax				    \n"	\
		     "movl %%eax, %%esp				    \n"	\
		     "movl $"__stringify(__NR_rt_sigreturn)", %%eax \n" \
		     "int $0x80					    \n"	\
		     :							\
		     : "r"(new_sp)					\
		     : "eax","esp","memory")
#endif /* CONFIG_X86_64 */

int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe,
		struct rt_sigframe *rsigframe);

#endif /* UAPI_COMPEL_ASM_SIGFRAME_H__ */
