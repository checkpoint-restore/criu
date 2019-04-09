/*
 * Don't include it directly but use "arch-sigframe.h" instead.
 */
#ifndef UAPI_COMPEL_SIGFRAME_COMMON_H__
#define UAPI_COMPEL_SIGFRAME_COMMON_H__

#ifndef UAPI_COMPEL_ASM_SIGFRAME_H__
# error "Direct inclusion is forbidden, use <compel/asm/sigframe.h> instead"
#endif

#include <signal.h>
#include <compel/plugins/std/asm/syscall-types.h>

struct rt_sigframe;

#ifndef SIGFRAME_MAX_OFFSET
# define SIGFRAME_MAX_OFFSET		RT_SIGFRAME_OFFSET(0)
#endif

#define RESTORE_STACK_ALIGN(x, a)	(((x) + (a) - 1) & ~((a) - 1))

/* sigframe should be aligned on 64 byte for x86 and 8 bytes for arm */
#define RESTORE_STACK_SIGFRAME		\
	RESTORE_STACK_ALIGN(sizeof(struct rt_sigframe) + SIGFRAME_MAX_OFFSET, 64)

#ifndef __ARCH_SI_PREAMBLE_SIZE
# define __ARCH_SI_PREAMBLE_SIZE	(3 * sizeof(int))
#endif

#define SI_MAX_SIZE	128

#ifndef SI_PAD_SIZE
# define SI_PAD_SIZE			((SI_MAX_SIZE - __ARCH_SI_PREAMBLE_SIZE) / sizeof(int))
#endif

typedef struct rt_siginfo {
	int	si_signo;
	int	si_errno;
	int	si_code;
	int	_pad[SI_PAD_SIZE];
} rt_siginfo_t;

typedef struct rt_sigaltstack {
	void	*ss_sp;
	int	ss_flags;
	size_t	ss_size;
} rt_stack_t;

struct rt_ucontext {
	unsigned long		uc_flags;
	struct rt_ucontext	*uc_link;
	rt_stack_t		uc_stack;
	struct rt_sigcontext	uc_mcontext;
	k_rtsigset_t		uc_sigmask;	/* mask last for extensibility */
	int                     _unused[32 - (sizeof (k_rtsigset_t) / sizeof (int))];
	unsigned long           uc_regspace[128] __attribute__((aligned(8)));
};

extern int sigreturn_prep_fpu_frame(struct rt_sigframe *frame,
				    struct rt_sigframe *rframe);

#endif /* UAPI_COMPEL_SIGFRAME_COMMON_H__ */
