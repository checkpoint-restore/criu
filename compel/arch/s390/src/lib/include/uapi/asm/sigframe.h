
#ifndef UAPI_COMPEL_ASM_SIGFRAME_H__
#define UAPI_COMPEL_ASM_SIGFRAME_H__

#include <asm/ptrace.h>
#include <asm/types.h>

#include <signal.h>
#include <stdint.h>

// XXX: the identifier rt_sigcontext is expected to be struct by the CRIU code
#define rt_sigcontext sigcontext

#include <compel/sigframe-common.h>

#define RT_SIGFRAME_OFFSET(rt_sigframe) 0

/*
 * From /usr/include/asm/sigcontext.h
 *
 * Redefine _sigregs_ext to be able to compile on older systems
 */
#ifndef __NUM_VXRS_LOW
typedef struct {
	__u32 u[4];
} __vector128;

typedef struct {
	unsigned long long vxrs_low[16];
	__vector128 vxrs_high[16];
	unsigned char __reserved[128];
} _sigregs_ext;
#endif

/*
 * From /usr/include/uapi/asm/ucontext.h
 */
struct ucontext_extended {
	unsigned long     uc_flags;
	ucontext_t       *uc_link;
	stack_t           uc_stack;
	_sigregs          uc_mcontext;
	sigset_t          uc_sigmask;
	/* Allow for uc_sigmask growth.  Glibc uses a 1024-bit sigset_t.  */
	unsigned char     __unused[128 - sizeof(sigset_t)];
	_sigregs_ext      uc_mcontext_ext;
};

/*
 * Signal stack frame for RT sigreturn
 */
struct rt_sigframe {
	uint8_t callee_used_stack[160];
	uint8_t retcode[2];
	siginfo_t info;
	struct ucontext_extended uc;
};

/*
 * Do rt_sigreturn SVC
 */
#define ARCH_RT_SIGRETURN(new_sp, rt_sigframe)			\
	asm volatile(						\
		"lgr	%%r15,%0\n"				\
		"lghi	%%r1,173\n"				\
		"svc	0\n"					\
		:						\
		: "d" (new_sp)					\
		: "15", "memory")

#define RT_SIGFRAME_UC(rt_sigframe) (&rt_sigframe->uc)
#define RT_SIGFRAME_REGIP(rt_sigframe) (rt_sigframe)->uc.uc_mcontext.regs.psw.addr
#define RT_SIGFRAME_HAS_FPU(rt_sigframe)	(1)

#endif /* UAPI_COMPEL_ASM_SIGFRAME_H__ */
