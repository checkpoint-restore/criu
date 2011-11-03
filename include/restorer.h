#ifndef CR_RESTORER_H__
#define CR_RESTORER_H__

#include <signal.h>

#include "compiler.h"
#include "types.h"
#include "image.h"

#ifndef CONFIG_X86_64
# error Only x86-64 is supported
#endif

#define RESTORER_ARGS_SIZE	512
#define RESTORER_STACK_REDZONE	(128)
#define RESTORER_STACK_FRAME	(16 << 10)
#define RESTORER_STACK_SIZE	(32 << 10)

extern long restorer(long cmd);

typedef long (*restorer_fcall_t) (long cmd);

#define RESTORER_CMD__NONE		0
#define RESTORER_CMD__GET_ARG_OFFSET	1
#define RESTORER_CMD__GET_SELF_LEN	2
#define RESTORER_CMD__PR_ARG_STRING	3
#define RESTORER_CMD__RESTORE_CORE	4

#define ABI_RED_ZONE 128

#define align_sigframe(sp)		round_down(sp, 16) - 8

struct restore_core_args {
	void	*self_entry;		/* restorer placed at */
	void	*rt_sigframe;		/* sigframe placed at */
	long	self_size;		/* size for restorer granted */
	char	core_path[64];		/* path to a core file */
	char	self_vmas_path[64];	/* path to a self-vmas file */
};

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
	struct user_fpregs_entry	*fpstate;
	unsigned long			reserved1[8];
};

#ifndef __ARCH_SI_PREAMBLE_SIZE
#define __ARCH_SI_PREAMBLE_SIZE	(3 * sizeof(int))
#endif

#define SI_MAX_SIZE	128
#ifndef SI_PAD_SIZE
#define SI_PAD_SIZE	((SI_MAX_SIZE - __ARCH_SI_PREAMBLE_SIZE) / sizeof(int))
#endif

typedef struct rt_siginfo {
	int	si_signo;
	int	si_errno;
	int	si_code;
	int	_pad[SI_PAD_SIZE];
} rt_siginfo_t;

typedef struct {
	unsigned long sig[1];
} rt_sigset_t;

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
	rt_sigset_t		uc_sigmask;	/* mask last for extensibility */
};

struct rt_sigframe {
	char			*pretcode;
	struct rt_ucontext	uc;
	struct rt_siginfo	info;

	/* fp state follows here */
};

#endif /* CR_RESTORER_H__ */
