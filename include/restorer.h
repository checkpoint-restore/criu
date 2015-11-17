#ifndef __CR_RESTORER_H__
#define __CR_RESTORER_H__

#include <signal.h>
#include <limits.h>
#include <sys/resource.h>

#include "compiler.h"
#include "asm/types.h"
#include "asm/fpu.h"
#include "image.h"
#include "lock.h"
#include "util.h"
#include "asm/restorer.h"
#include "rst_info.h"
#include "config.h"

#include "posix-timer.h"
#include "timerfd.h"
#include "shmem.h"
#include "sigframe.h"
#include "parasite-vdso.h"

#include <time.h>

#include "protobuf/mm.pb-c.h"
#include "protobuf/vma.pb-c.h"
#include "protobuf/creds.pb-c.h"
#include "protobuf/core.pb-c.h"

struct task_restore_core_args;
struct thread_restore_args;

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
#define RESTORE_STACK_SIZE		(KILO(32))

struct restore_mem_zone {
	u8				redzone[RESTORE_STACK_REDZONE];
	u8				stack[RESTORE_STACK_SIZE];
	u8				rt_sigframe[RESTORE_STACK_SIGFRAME];
} __aligned(sizeof(long));

struct rst_sched_param {
	int policy;
	int nice;
	int prio;
};

struct restore_posix_timer {
	struct str_posix_timer spt;
	struct itimerspec val;
	int overrun;
};

struct task_restore_core_args;

/*
 * We should be able to construct fpu sigframe in sigreturn_prep_fpu_frame,
 * so the mem_zone.rt_sigframe should be 64-bytes aligned. To make things
 * simpler, force both _args alignment be 64 bytes.
 */

struct thread_restore_args {
	struct restore_mem_zone		mem_zone;

	int				pid;
	UserRegsEntry			gpregs;
	u64				clear_tid_addr;

	bool				has_futex;
	u64				futex_rla;
	u32				futex_rla_len;

	struct rst_sched_param		sp;

	struct task_restore_args	*ta;

	tls_t				tls;

	siginfo_t			*siginfo;
	unsigned int			siginfo_n;

	int				pdeath_sig;
} __aligned(64);

struct task_restore_args {
	struct thread_restore_args	*t;			/* thread group leader */

	int				fd_exe_link;		/* opened self->exe file */
	int				logfd;
	unsigned int			loglevel;

	/* threads restoration */
	int				nr_threads;		/* number of threads */
	thread_restore_fcall_t		clone_restore_fn;	/* helper address for clone() call */
	struct thread_restore_args	*thread_args;		/* array of thread arguments */
	struct task_entries		*task_entries;
	void				*rst_mem;
	unsigned long			rst_mem_size;

	/* Below arrays get remapped from RM_PRIVATE in sigreturn_restore */
	VmaEntry			*vmas;
	unsigned int			vmas_n;

	struct restore_posix_timer	*posix_timers;
	unsigned int			posix_timers_n;

	struct restore_timerfd		*timerfd;
	unsigned int			timerfd_n;

	siginfo_t			*siginfo;
	unsigned int			siginfo_n;

	struct rst_tcp_sock		*tcp_socks;
	unsigned int			tcp_socks_n;

	struct rst_aio_ring		*rings;
	unsigned int			rings_n;

	struct rlimit			*rlims;
	unsigned int			rlims_n;

	pid_t				*helpers /* the TASK_HELPERS to wait on at the end of restore */;
	unsigned int			helpers_n;

	pid_t				*zombies;
	unsigned int			zombies_n;

	struct sock_fprog		*seccomp_filters;
	unsigned int			seccomp_filters_n;

	/* * * * * * * * * * * * * * * * * * * * */

	unsigned long			task_size;
	unsigned long			premmapped_addr;
	unsigned long			premmapped_len;
	rt_sigaction_t			sigchld_act;

	void				*bootstrap_start;
	unsigned long			bootstrap_len;

	struct itimerval		itimers[3];

	CredsEntry			creds;
	u32				cap_inh[CR_CAP_SIZE];
	u32				cap_prm[CR_CAP_SIZE];
	u32				cap_eff[CR_CAP_SIZE];
	u32				cap_bnd[CR_CAP_SIZE];
	u32				cap_last_cap;

	MmEntry				mm;
	auxv_t				mm_saved_auxv[AT_VECTOR_SIZE];
	u32				mm_saved_auxv_size;
	char				comm[TASK_COMM_LEN];

	/*
	 * proc_fd is a handle to /proc that the restorer blob can use to open
	 * files there, because some of them can't be opened before the
	 * restorer blob is called.
	 */
	int				proc_fd;

	int				seccomp_mode;

#ifdef CONFIG_VDSO
	unsigned long			vdso_rt_size;
	struct vdso_symtable		vdso_sym_rt;		/* runtime vdso symbols */
	unsigned long			vdso_rt_parked_at;	/* safe place to keep vdso */
#endif
	void				**breakpoint;
} __aligned(64);

#define RESTORE_ALIGN_STACK(start, size)	\
	(ALIGN((start) + (size) - sizeof(long), sizeof(long)))

static inline unsigned long restorer_stack(struct thread_restore_args *a)
{
	return RESTORE_ALIGN_STACK((long)a->mem_zone.stack, RESTORE_STACK_SIZE);
}

enum {
	CR_STATE_FAIL		= -1,
	CR_STATE_RESTORE_NS	= 0, /* is used for executing "setup-namespace" scripts */
	CR_STATE_RESTORE_SHARED,
	CR_STATE_FORKING,
	CR_STATE_RESTORE,
	CR_STATE_RESTORE_SIGCHLD,
	/*
	 * For security reason processes can be resumed only when all
	 * credentials are restored. Otherwise someone can attach to a
	 * process, which are not restored credentials yet and execute
	 * some code.
	 */
	CR_STATE_RESTORE_CREDS,
	CR_STATE_COMPLETE
};

#define restore_finish_stage(__stage) ({				\
		futex_dec_and_wake(&task_entries->nr_in_progress);	\
		futex_wait_while(&task_entries->start, __stage);	\
		(s32) futex_get(&task_entries->start);			\
	})


/* the restorer_blob_offset__ prefix is added by gen_offsets.sh */
#define __blob_offset(name)	restorer_blob_offset__ ## name
#define _blob_offset(name)	__blob_offset(name)
#define restorer_sym(rblob, name)	(void*)(rblob + _blob_offset(name))

#endif /* __CR_RESTORER_H__ */
