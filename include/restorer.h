#ifndef CR_RESTORER_H__
#define CR_RESTORER_H__

#include <signal.h>
#include <limits.h>

#include "compiler.h"
#include "types.h"
#include "image.h"

#ifndef CONFIG_X86_64
# error Only x86-64 is supported
#endif

/*
 * These must! be power of two values.
 */
#define RESTORE_ARGS_SIZE		(512)
#define RESTORE_STACK_REDZONE		(128)
#define RESTORE_STACK_FRAME		(16 << 10)
#define RESTORE_THREAD_STACK_SIZE	(16 << 10)
#define RESTORE_THREAD_HEAP_SIZE	(16 << 10)
#define RESTORE_STACK_SIZE		(32 << 10)

#define RESTORE_CMD__NONE		0
#define RESTORE_CMD__GET_ARG_OFFSET	1
#define RESTORE_CMD__GET_SELF_LEN	2
#define RESTORE_CMD__PR_ARG_STRING	3
#define RESTORE_CMD__RESTORE_CORE	4
#define RESTORE_CMD__RESTORE_THREAD	5

#define ABI_RED_ZONE 128

#define align_sigframe(sp)		round_down(sp, 16) - 8

typedef u32 rlock_t;
#define RLOCK_T(v) rlock_t v __aligned(sizeof(u32)) = 0

/* Make sure it's pow2 in size */
struct thread_restore_args {
	u32				pid;
	u32				fd_core;
	rlock_t				*lock;

	u8				stack[RESTORE_THREAD_STACK_SIZE];
	union {
		struct core_entry	core_entry;
		u8			heap[RESTORE_THREAD_HEAP_SIZE];
	} __aligned(sizeof(long));
	u8				rt_sigframe[RESTORE_STACK_FRAME];
};

extern long restore_task(long cmd);
extern long restore_thread(long cmd, struct thread_restore_args *args);

typedef long (*task_restore_fcall_t) (long cmd);
typedef long (*thread_restore_fcall_t) (long cmd, struct thread_restore_args *args);

struct task_restore_core_args {
	void				*self_entry;		/* restorer placed at */
	void				*rt_sigframe;		/* sigframe placed at */
	long				self_size;		/* size for restorer granted */
	char				core_path[64];
	char				self_vmas_path[64];
	u32				pid;
	rlock_t				*lock;

	/* threads restoration specifics */
	thread_restore_fcall_t		clone_restore_fn;	/* helper address for clone() call */
	long				nr_threads;		/* number of threads */
	struct thread_restore_args	*thread_args;		/* array of thread arguments */
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

#define add_ord(c)			\
	do {				\
		if (c < 10)		\
			c += '0';	\
		else			\
			c += 'a' - 10;	\
	} while (0)

static void always_inline write_char(char c)
{
	sys_write(1, &c, 1);
}

static void always_inline write_string(char *str)
{
	int len = 0;

	while (str[len])
		len++;

	sys_write(1, str, len);
}

static void always_inline write_string_n(char *str)
{
	char new_line = '\n';

	write_string(str);
	sys_write(1, &new_line, 1);
}

static void always_inline write_hex_n(unsigned long num)
{
	unsigned char *s = (unsigned char *)&num;
	unsigned char c;
	int i;

	for (i = sizeof(long)/sizeof(char) - 1; i >= 0; i--) {
		c = (s[i] & 0xf0) >> 4;
		add_ord(c);
		sys_write(1, &c, 1);

		c = (s[i] & 0x0f);
		add_ord(c);
		sys_write(1, &c, 1);
	}

	c = '\n';
	sys_write(1, &c, 1);
}

#define FUTEX_WAIT		0
#define FUTEX_WAKE		1
#define FUTEX_FD		2
#define FUTEX_REQUEUE		3
#define FUTEX_CMP_REQUEUE	4
#define FUTEX_WAKE_OP		5
#define FUTEX_LOCK_PI		6
#define FUTEX_UNLOCK_PI		7
#define FUTEX_TRYLOCK_PI	8
#define FUTEX_WAIT_BITSET	9
#define FUTEX_WAKE_BITSET	10
#define FUTEX_WAIT_REQUEUE_PI	11
#define FUTEX_CMP_REQUEUE_PI	12

static always_inline void r_lock(rlock_t *v)
{
	while (*v) {
		asm volatile("lfence");
		asm volatile("pause");
	}
	(*v)++;

	asm volatile("sfence");
}

static always_inline void r_unlock(rlock_t *v)
{
	(*v)--;
	asm volatile("sfence");
}

static always_inline void r_wait_unlock(rlock_t *v)
{
	while (*v) {
		asm volatile("lfence");
		asm volatile("pause");
	}
}

#endif /* CR_RESTORER_H__ */
