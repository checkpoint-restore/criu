#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include "asm/types.h"
#include "asm/fpu.h"
#include "protobuf/core.pb-c.h"

struct pt_regs {
	unsigned long	r15;
	unsigned long	r14;
	unsigned long	r13;
	unsigned long	r12;
	unsigned long	bp;
	unsigned long	bx;

	unsigned long	r11;
	unsigned long	r10;
	unsigned long	r9;
	unsigned long	r8;
	unsigned long	ax;
	unsigned long	cx;
	unsigned long	dx;
	unsigned long	si;
	unsigned long	di;
	unsigned long	orig_ax;

	unsigned long	ip;
	unsigned long	cs;
	unsigned long	flags;
	unsigned long	sp;
	unsigned long	ss;
};

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
	unsigned short			__pad0;
	unsigned long			err;
	unsigned long			trapno;
	unsigned long			oldmask;
	unsigned long			cr2;
	void				*fpstate;
	unsigned long			reserved1[8];
};

#include "sigframe.h"

struct rt_sigframe {
	char			*pretcode;
	struct rt_ucontext	uc;
	struct rt_siginfo	info;

	fpu_state_t		fpu_state;
};


#define ARCH_RT_SIGRETURN(new_sp)					\
	asm volatile(							\
		     "movq %0, %%rax				    \n"	\
		     "movq %%rax, %%rsp				    \n"	\
		     "movl $"__stringify(__NR_rt_sigreturn)", %%eax \n" \
		     "syscall					    \n"	\
		     :							\
		     : "r"(new_sp)					\
		     : "rax","rsp","memory")

#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,      \
			     thread_args, clone_restore_fn)             \
	asm volatile(							\
		     "clone_emul:				\n"	\
		     "movq %2, %%rsi				\n"	\
		     "subq $16, %%rsi			        \n"	\
		     "movq %6, %%rdi				\n"	\
		     "movq %%rdi, 8(%%rsi)			\n"	\
		     "movq %5, %%rdi				\n"	\
		     "movq %%rdi, 0(%%rsi)			\n"	\
		     "movq %1, %%rdi				\n"	\
		     "movq %3, %%rdx				\n"	\
		     "movq %4, %%r10				\n"	\
		     "movl $"__stringify(__NR_clone)", %%eax	\n"	\
		     "syscall				        \n"	\
									\
		     "testq %%rax,%%rax			        \n"	\
		     "jz thread_run				\n"	\
									\
		     "movq %%rax, %0				\n"	\
		     "jmp clone_end				\n"	\
									\
		     "thread_run:				\n"	\
		     "xorq %%rbp, %%rbp			        \n"	\
		     "popq %%rax				\n"	\
		     "popq %%rdi				\n"	\
		     "callq *%%rax				\n"	\
									\
		     "clone_end:				\n"	\
		     : "=r"(ret)					\
		     : "g"(clone_flags),				\
		       "g"(new_sp),					\
		       "g"(&parent_tid),				\
		       "g"(&thread_args[i].pid),			\
		       "g"(clone_restore_fn),				\
		       "g"(&thread_args[i])				\
		     : "rax", "rdi", "rsi", "rdx", "r10", "memory")

#define ARCH_FAIL_CORE_RESTORE					\
	asm volatile(						\
		     "movq %0, %%rsp			    \n"	\
		     "movq 0, %%rax			    \n"	\
		     "jmp *%%rax			    \n"	\
		     :						\
		     : "r"(ret)					\
		     : "memory")

#define RT_SIGFRAME_UC(rt_sigframe) rt_sigframe->uc
#define RT_SIGFRAME_REGIP(rt_sigframe) (rt_sigframe)->uc.uc_mcontext.rip
#define RT_SIGFRAME_HAS_FPU(rt_sigframe) (rt_sigframe)->fpu_state.has_fpu
#define RT_SIGFRAME_FPU(rt_sigframe) (rt_sigframe)->fpu_state

#define SIGFRAME_OFFSET 8


int restore_gpregs(struct rt_sigframe *f, UserX86RegsEntry *r);
int restore_nonsigframe_gpregs(UserX86RegsEntry *r);

int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe, fpu_state_t *fpu_state);

static inline void restore_tls(tls_t *ptls) { (void)ptls; }

int ptrace_set_breakpoint(pid_t pid, void *addr);
int ptrace_flush_breakpoints(pid_t pid);


#endif
