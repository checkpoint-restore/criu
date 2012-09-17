#ifndef CR_RESTORER_H__
#define CR_RESTORER_H__

#include <signal.h>
#include <limits.h>

#include "compiler.h"
#include "types.h"
#include "image.h"
#include "lock.h"
#include "util.h"
#include "crtools.h"

#include "../protobuf/mm.pb-c.h"
#include "../protobuf/vma.pb-c.h"
#include "../protobuf/creds.pb-c.h"
#include "../protobuf/core.pb-c.h"

#ifndef CONFIG_X86_64
# error Only x86-64 is supported
#endif

struct task_restore_core_args;
struct thread_restore_args;

extern long __export_restore_task(struct task_restore_core_args *args);
extern long __export_restore_thread(struct thread_restore_args *args);

typedef long (*task_restore_fcall_t) (struct task_restore_core_args *args);
typedef long (*thread_restore_fcall_t) (struct thread_restore_args *args);

#define RESTORE_CMD__NONE		0
#define RESTORE_CMD__GET_SELF_LEN	1
#define RESTORE_CMD__RESTORE_CORE	2
#define RESTORE_CMD__RESTORE_THREAD	3

/*
 * These *must* be power of two values.
 */
#define RESTORE_ARGS_SIZE		(512)
#define RESTORE_STACK_REDZONE		(128)
#define RESTORE_STACK_SIGFRAME		(KILO(16))
#define RESTORE_STACK_SIZE		(KILO(32))
#define RESTORE_HEAP_SIZE		(KILO(16))

#define RESTORE_ALIGN_STACK(start, size)	\
	(ALIGN((start) + (size) - sizeof(long), sizeof(long)))

struct restore_mem_zone {
	u8				redzone[RESTORE_STACK_REDZONE];
	u8				stack[RESTORE_STACK_SIZE];
	u8				rt_sigframe[RESTORE_STACK_SIGFRAME];
	u8				heap[RESTORE_HEAP_SIZE];
} __aligned(sizeof(long));

#define first_on_heap(ptr, heap)	((typeof(ptr))heap)
#define next_on_heap(ptr, prev)		((typeof(ptr))((long)(prev) + sizeof(*(prev))))

/* Make sure it's pow2 in size */
struct thread_restore_args {
	struct restore_mem_zone		mem_zone;

	int				pid;
	mutex_t				*rst_lock;
	UserX86RegsEntry		gpregs;
	u64				clear_tid_addr;

	bool				has_futex;
	u64				futex_rla;
	u32				futex_rla_len;
} __aligned(sizeof(long));

struct task_restore_core_args {
	struct restore_mem_zone		mem_zone;

	int				pid;			/* task pid */
	int				fd_exe_link;		/* opened self->exe file */
	int				fd_pages;		/* opened pages dump file */
	int				logfd;
	unsigned int			loglevel;
	bool				restore_threads;	/* if to restore threads */
	mutex_t				rst_lock;

	/* threads restoration */
	int				nr_threads;		/* number of threads */
	thread_restore_fcall_t		clone_restore_fn;	/* helper address for clone() call */
	struct thread_restore_args	*thread_args;		/* array of thread arguments */
	struct shmems			*shmems;
	struct task_entries		*task_entries;
	VmaEntry			*self_vmas;
	VmaEntry			*tgt_vmas;
	rt_sigaction_t			sigchld_act;

	struct itimerval		itimers[3];

	CredsEntry			creds;
	uint32_t			cap_inh[CR_CAP_SIZE];
	uint32_t			cap_prm[CR_CAP_SIZE];
	uint32_t			cap_eff[CR_CAP_SIZE];
	uint32_t			cap_bnd[CR_CAP_SIZE];

	MmEntry				mm;
	u64				mm_saved_auxv[AT_VECTOR_SIZE];
	u64				clear_tid_addr;
	u64				blk_sigset;
	char				comm[TASK_COMM_LEN];
	TaskKobjIdsEntry		ids;
	UserX86RegsEntry		gpregs;

	bool				has_futex;
	u64				futex_rla;
	u32				futex_rla_len;

	int				*rst_tcp_socks;
	int				rst_tcp_socks_size;
} __aligned(sizeof(long));

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


#define SHMEMS_SIZE	4096

/*
 * pid is a pid of a creater
 * start, end are used for open mapping
 * fd is a file discriptor, which is valid for creater,
 * it's opened in cr-restor, because pgoff may be non zero
 */

struct shmem_info {
	unsigned long	shmid;
	unsigned long	start;
	unsigned long	end;
	unsigned long	size;
	int		pid;
	int		fd;
	futex_t		lock;
};

struct shmems {
	int			nr_shmems;
	struct shmem_info	entries[0];
};

#define TASK_ENTRIES_SIZE 4096

enum {
	CR_STATE_FORKING,
	CR_STATE_RESTORE_PGID,
	CR_STATE_RESTORE,
	CR_STATE_RESTORE_SIGCHLD,
	CR_STATE_COMPLETE
};

struct task_entries {
	int nr, nr_tasks, nr_helpers;
	futex_t nr_in_progress;
	futex_t start;
};

static always_inline struct shmem_info *
find_shmem(struct shmems *shmems, unsigned long shmid)
{
	struct shmem_info *si;
	int i;

	for (i = 0; i < shmems->nr_shmems; i++) {
		si = &shmems->entries[i];
		if (si->shmid == shmid)
			return si;
	}

	return NULL;
}

#endif /* CR_RESTORER_H__ */
