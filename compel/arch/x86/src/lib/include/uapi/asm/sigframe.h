#ifndef UAPI_COMPEL_ASM_SIGFRAME_H__
#define UAPI_COMPEL_ASM_SIGFRAME_H__

#include <stdint.h>
#include <stdbool.h>

#include <compel/asm/fpu.h>
#include <compel/plugins/std/syscall-codes.h>

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

struct rt_sigcontext_32 {
	uint32_t			gs;
	uint32_t			fs;
	uint32_t			es;
	uint32_t			ds;
	uint32_t			di;
	uint32_t			si;
	uint32_t			bp;
	uint32_t			sp;
	uint32_t			bx;
	uint32_t			dx;
	uint32_t			cx;
	uint32_t			ax;
	uint32_t			trapno;
	uint32_t			err;
	uint32_t			ip;
	uint32_t			cs;
	uint32_t			flags;
	uint32_t			sp_at_signal;
	uint32_t			ss;

	uint32_t			fpstate;
	uint32_t			oldmask;
	uint32_t			cr2;
};

#include <compel/sigframe-common.h>

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

struct ucontext_ia32 {
	unsigned int		uc_flags;
	unsigned int		uc_link;
	compat_stack_t		uc_stack;
	struct rt_sigcontext_32	uc_mcontext;
	k_rtsigset_t		uc_sigmask; /* mask last for extensibility */
} __packed;

struct rt_sigframe_ia32 {
	uint32_t		pretcode;
	int32_t			sig;
	uint32_t		pinfo;
	uint32_t		puc;
	compat_siginfo_t	info;
	struct ucontext_ia32	uc;
	char			retcode[8];

	/* fp state follows here */
	fpu_state_t		fpu_state;
};

struct rt_sigframe_64 {
	char			*pretcode;
	struct rt_ucontext	uc;
	struct rt_siginfo	info;

	/* fp state follows here */
	fpu_state_t		fpu_state;
};

struct rt_sigframe {
	union {
		struct rt_sigframe_ia32	compat;
		struct rt_sigframe_64	native;
	};
	bool is_native;
};

#define RT_SIGFRAME_UC_SIGMASK(rt_sigframe)				\
	((rt_sigframe->is_native)			?		\
	(&rt_sigframe->native.uc.uc_sigmask) :				\
	(&rt_sigframe->compat.uc.uc_sigmask))

#define RT_SIGFRAME_REGIP(rt_sigframe)					\
	((rt_sigframe->is_native)			?		\
	(rt_sigframe)->native.uc.uc_mcontext.rip :			\
	(rt_sigframe)->compat.uc.uc_mcontext.ip)

#define RT_SIGFRAME_FPU(rt_sigframe)					\
	((rt_sigframe->is_native)			?		\
	(&(rt_sigframe)->native.fpu_state)		:		\
	 (&(rt_sigframe)->compat.fpu_state))

#define RT_SIGFRAME_HAS_FPU(rt_sigframe) (RT_SIGFRAME_FPU(rt_sigframe)->has_fpu)

/*
 * Sigframe offset is different for native/compat tasks.
 * Offsets calculations one may see at kernel:
 * - compatible is in sys32_rt_sigreturn at arch/x86/ia32/ia32_signal.c
 * - native is in sys_rt_sigreturn at arch/x86/kernel/signal.c
 */
#define RT_SIGFRAME_OFFSET(rt_sigframe)	(((rt_sigframe)->is_native) ? 8 : 4 )

#define USER32_CS		0x23

#define ARCH_RT_SIGRETURN_NATIVE(new_sp)				\
	asm volatile(							\
		     "movq %0, %%rax				    \n"	\
		     "movq %%rax, %%rsp				    \n"	\
		     "movl $"__stringify(__NR_rt_sigreturn)", %%eax \n" \
		     "syscall					    \n"	\
		     :							\
		     : "r"(new_sp)					\
		     : "rax","rsp","memory")
#define ARCH_RT_SIGRETURN_COMPAT(new_sp)				\
	asm volatile(							\
		"pushq $"__stringify(USER32_CS)"		\n"	\
		"pushq $1f					\n"	\
		"lretq						\n"	\
		"1:						\n"	\
		".code32					\n"	\
		"movl %%edi, %%esp				\n"	\
		"movl $"__stringify(__NR32_rt_sigreturn)",%%eax	\n"	\
		"int $0x80					\n"	\
		".code64					\n"	\
		:							\
		: "rdi"(new_sp)						\
		: "eax","esp", "r8", "r9", "r10", "r11", "memory")

#define ARCH_RT_SIGRETURN(new_sp, rt_sigframe)				\
do {									\
	if ((rt_sigframe)->is_native)					\
		ARCH_RT_SIGRETURN_NATIVE(new_sp);			\
	else								\
		ARCH_RT_SIGRETURN_COMPAT(new_sp);			\
} while (0)

int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe,
		struct rt_sigframe *rsigframe);

#endif /* UAPI_COMPEL_ASM_SIGFRAME_H__ */
