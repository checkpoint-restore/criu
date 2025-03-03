#ifndef __COMPEL_INFECT_H__
#define __COMPEL_INFECT_H__

#include <stdbool.h>

#include <compel/asm/sigframe.h>
#include <compel/asm/infect-types.h>
#include <compel/ksigset.h>
#include <compel/handle-elf.h>
#include <compel/task-state.h>

#include "common/compiler.h"

#define PARASITE_START_AREA_MIN (4096)

extern int __must_check compel_interrupt_task(int pid);

struct seize_task_status {
	unsigned long long sigpnd;
	unsigned long long shdpnd;
	unsigned long long sigblk;
	char state;
	int vpid;
	int ppid;
	int seccomp_mode;
};

extern int __must_check compel_wait_task(int pid, int ppid,
					 int (*get_status)(int pid, struct seize_task_status *, void *data),
					 void (*free_status)(int pid, struct seize_task_status *, void *data),
					 struct seize_task_status *st, void *data);

extern int __must_check compel_stop_task(int pid);
extern int __must_check compel_parse_stop_signo(int pid);
extern int compel_resume_task(pid_t pid, int orig_state, int state);
extern int compel_resume_task_sig(pid_t pid, int orig_state, int state, int stop_signo);

struct parasite_ctl;
struct parasite_thread_ctl;

extern struct parasite_ctl __must_check *compel_prepare(int pid);
extern struct parasite_ctl __must_check *compel_prepare_noctx(int pid);
extern int __must_check compel_infect(struct parasite_ctl *ctl, unsigned long nr_threads, unsigned long args_size);
extern int __must_check compel_infect_no_daemon(struct parasite_ctl *ctl, unsigned long nr_threads,
						unsigned long args_size);
extern struct parasite_thread_ctl __must_check *compel_prepare_thread(struct parasite_ctl *ctl, int pid);
extern void compel_release_thread(struct parasite_thread_ctl *);

extern int __must_check compel_start_daemon(struct parasite_ctl *ctl);
extern int __must_check compel_stop_daemon(struct parasite_ctl *ctl);
extern int __must_check compel_cure_remote(struct parasite_ctl *ctl);
extern int __must_check compel_cure_local(struct parasite_ctl *ctl);
extern int __must_check compel_cure(struct parasite_ctl *ctl);

#define PARASITE_ARG_SIZE_MIN (1 << 12)

#define compel_parasite_args(ctl, type)                             \
	({                                                          \
		void *___ret;                                       \
		BUILD_BUG_ON(sizeof(type) > PARASITE_ARG_SIZE_MIN); \
		___ret = compel_parasite_args_p(ctl);               \
		___ret;                                             \
	})

extern void *compel_parasite_args_p(struct parasite_ctl *ctl);
extern void *compel_parasite_args_s(struct parasite_ctl *ctl, unsigned long args_size);

extern int __must_check compel_syscall(struct parasite_ctl *ctl, int nr, long *ret, unsigned long arg1,
				       unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5,
				       unsigned long arg6);
extern int __must_check compel_run_in_thread(struct parasite_thread_ctl *tctl, unsigned int cmd);
extern int __must_check compel_run_at(struct parasite_ctl *ctl, unsigned long ip, user_regs_struct_t *ret_regs);

/*
 * The PTRACE_SYSCALL will trap task twice -- on
 * enter into and on exit from syscall. If we trace
 * a single task, we may skip half of all getregs
 * calls -- on exit we don't need them.
 */
enum trace_flags {
	TRACE_ALL,
	TRACE_ENTER,
	TRACE_EXIT,
};

extern int __must_check compel_stop_on_syscall(int tasks, int sys_nr, int sys_nr_compat);

extern int __must_check compel_stop_pie(pid_t pid, void *addr, bool no_bp);

extern int __must_check compel_unmap(struct parasite_ctl *ctl, unsigned long addr);

extern int compel_mode_native(struct parasite_ctl *ctl);

extern k_rtsigset_t *compel_task_sigmask(struct parasite_ctl *ctl);
extern k_rtsigset_t *compel_thread_sigmask(struct parasite_thread_ctl *tctl);

struct rt_sigframe;

typedef int (*open_proc_fn)(int pid, int mode, const char *fmt, ...) __attribute__((__format__(__printf__, 3, 4)));
typedef int (*save_regs_t)(pid_t pid, void *, user_regs_struct_t *, user_fpregs_struct_t *);
typedef int (*make_sigframe_t)(void *, struct rt_sigframe *, struct rt_sigframe *, k_rtsigset_t *);

struct infect_ctx {
	int sock;

	/*
	 * Regs manipulation context.
	 */
	save_regs_t save_regs;
	make_sigframe_t make_sigframe;
	void *regs_arg;

	unsigned long task_size;
	unsigned long syscall_ip; /* entry point of infection */
	unsigned long flags;	  /* fine-tune (e.g. faults) */

	void (*child_handler)(int, siginfo_t *, void *); /* handler for SIGCHLD deaths */
	struct sigaction orig_handler;

	open_proc_fn open_proc;

	int log_fd; /* fd for parasite code to send messages to */
	unsigned long remote_map_addr; /* User-specified address where to mmap parasitic code, default not set */
};

extern struct infect_ctx *compel_infect_ctx(struct parasite_ctl *);

/* Don't use memfd() */
#define INFECT_NO_MEMFD (1UL << 0)
/* Make parasite connect() fail */
#define INFECT_FAIL_CONNECT (1UL << 1)
/* No breakpoints in pie tracking */
#define INFECT_NO_BREAKPOINTS (1UL << 2)
/* Can run parasite inside compat tasks */
#define INFECT_COMPATIBLE (1UL << 3)
/* Workaround for ptrace bug on Skylake CPUs with kernels older than v4.14 */
#define INFECT_X86_PTRACE_MXCSR_BUG (1UL << 4)
/* After infecting - corrupt extended registers (fault-injection) */
#define INFECT_CORRUPT_EXTREGS (1UL << 5)

/*
 * There are several ways to describe a blob to compel
 * library. The simplest one derived from criu is to
 * provide it from .h files.
 */
#define COMPEL_BLOB_CHEADER 0x1

struct parasite_blob_desc {
	unsigned parasite_type;
	union {
		struct {
			const void *mem;
			size_t bsize;
			unsigned long parasite_ip_off;
			unsigned long cmd_off;
			unsigned long args_ptr_off;
			unsigned long got_off;
			unsigned long args_off;
			unsigned long data_off;
			compel_reloc_t *relocs;
			unsigned int nr_relocs;
		} hdr;
	};
};

extern struct parasite_blob_desc *compel_parasite_blob_desc(struct parasite_ctl *);

extern int __must_check compel_get_thread_regs(struct parasite_thread_ctl *, save_regs_t, void *);

extern void compel_relocs_apply(void *mem, void *vbase, struct parasite_blob_desc *pbd);
extern void compel_relocs_apply_mips(void *mem, void *vbase, struct parasite_blob_desc *pbd);

extern unsigned long compel_task_size(void);

extern uint64_t compel_get_leader_sp(struct parasite_ctl *ctl);
extern uint64_t compel_get_thread_sp(struct parasite_thread_ctl *tctl);

extern uint64_t compel_get_leader_ip(struct parasite_ctl *ctl);
extern uint64_t compel_get_thread_ip(struct parasite_thread_ctl *tctl);

void compel_set_leader_ip(struct parasite_ctl *ctl, uint64_t v);
void compel_set_thread_ip(struct parasite_thread_ctl *tctl, uint64_t v);

extern void compel_get_stack(struct parasite_ctl *ctl, void **rstack, void **r_thread_stack);

#ifndef compel_shstk_enabled
static inline bool compel_shstk_enabled(user_fpregs_struct_t *ext_regs)
{
	return false;
}
#define compel_shstk_enabled
#endif

#ifndef parasite_setup_shstk
static inline int parasite_setup_shstk(struct parasite_ctl *ctl,
				       user_fpregs_struct_t *ext_regs)
{
	return 0;
}
#define parasite_setup_shstk parasite_setup_shstk
#endif

#endif
