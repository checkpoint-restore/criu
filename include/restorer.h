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
#include "crtools.h"

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

struct rst_sched_param {
	int policy;
	int nice;
	int prio;
};

struct task_restore_core_args;

/* Make sure it's pow2 in size */
struct thread_restore_args {
	struct restore_mem_zone		mem_zone;

	int				pid;
	UserRegsEntry		        gpregs;
	u64				clear_tid_addr;

	bool				has_futex;
	u64				futex_rla;
	u32				futex_rla_len;

	bool				has_blk_sigset;
	k_rtsigset_t			blk_sigset;

	struct rst_sched_param		sp;

	struct task_restore_core_args	*ta;

	bool				has_fpu;
	fpu_state_t			fpu_state;

	u32				tls;

	siginfo_t			*siginfo;
	unsigned int			siginfo_nr;
} __aligned(sizeof(long));

struct task_restore_core_args {
	struct thread_restore_args	*t;			/* thread group leader */

	int				fd_exe_link;		/* opened self->exe file */
	int				logfd;
	unsigned int			loglevel;

	mutex_t				rst_lock;

	/* threads restoration */
	int				nr_threads;		/* number of threads */
	int				nr_zombies;
	thread_restore_fcall_t		clone_restore_fn;	/* helper address for clone() call */
	struct thread_restore_args	*thread_args;		/* array of thread arguments */
	struct shmems			*shmems;
	struct task_entries		*task_entries;
	VmaEntry			*self_vmas;
	VmaEntry			*tgt_vmas;
	siginfo_t			*siginfo;
	unsigned int			siginfo_nr;
	unsigned long			siginfo_size;
	unsigned int			nr_vmas;
	unsigned long			premmapped_addr;
	unsigned long			premmapped_len;
	rt_sigaction_t			sigchld_act;

	struct itimerval		itimers[3];

	CredsEntry			creds;
	uint32_t			cap_inh[CR_CAP_SIZE];
	uint32_t			cap_prm[CR_CAP_SIZE];
	uint32_t			cap_eff[CR_CAP_SIZE];
	uint32_t			cap_bnd[CR_CAP_SIZE];
	uint32_t			cap_last_cap;

	MmEntry				mm;
	auxv_t				mm_saved_auxv[AT_VECTOR_SIZE];
	u32				mm_saved_auxv_size;
	char				comm[TASK_COMM_LEN];

	int				nr_rlim;
	struct rlimit			rlims[RLIM_NLIMITS];

	struct rst_tcp_sock		*rst_tcp_socks;
	int				rst_tcp_socks_size;
} __aligned(sizeof(long));

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
	/*
	 * For security reason processes can be resumed only when all
	 * credentials are restored. Otherwise someone can attach to a
	 * process, which are not restored credentials yet and execute
	 * some code.
	 */
	CR_STATE_RESTORE_CREDS,
	CR_STATE_COMPLETE
};

struct task_entries {
	int nr_threads, nr_tasks, nr_helpers;
	futex_t nr_in_progress;
	futex_t start;
	mutex_t	zombie_lock;
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

#define restore_finish_stage(__stage) do {				\
		futex_dec_and_wake(&task_entries->nr_in_progress);	\
		futex_wait_while(&task_entries->start, __stage);	\
	} while (0)


/* the restorer_blob_offset__ prefix is added by gen_offsets.sh */
#define restorer_sym(rblob, name)	((void *)(rblob) + restorer_blob_offset__##name)

#define vma_priv(vma) ((vma_entry_is(vma, VMA_AREA_REGULAR)) &&	\
			(vma_entry_is(vma, VMA_ANON_PRIVATE) || \
			vma_entry_is(vma, VMA_FILE_PRIVATE)))

#endif /* __CR_RESTORER_H__ */
