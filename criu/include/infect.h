#ifndef __COMPEL_INFECT_H__
#define __COMPEL_INFECT_H__

#include "asm/infect-types.h"
#include <compel/ksigset.h>

#define PARASITE_START_AREA_MIN	(4096)

extern int compel_stop_task(int pid);

struct seize_task_status {
	char			state;
	int			ppid;
	unsigned long long	sigpnd;
	unsigned long long	shdpnd;
	int			seccomp_mode;
};

extern int compel_wait_task(int pid, int ppid,
		int (*get_status)(int pid, struct seize_task_status *),
		struct seize_task_status *st);
extern int compel_unseize_task(pid_t pid, int orig_state, int state);

/*
 * FIXME -- these should be mapped to pid.h's
 */

#define TASK_ALIVE		0x1
#define TASK_DEAD		0x2
#define TASK_STOPPED		0x3
#define TASK_ZOMBIE		0x6

struct parasite_ctl;
struct thread_ctx {
	k_rtsigset_t		sigmask;
	user_regs_struct_t	regs;
};

extern struct parasite_ctl *compel_prepare(int pid);
extern int compel_infect(struct parasite_ctl *ctl, unsigned long nr_threads, unsigned long args_size);
extern int compel_prepare_thread(int pid, struct thread_ctx *ctx);

extern int compel_stop_daemon(struct parasite_ctl *ctl);
extern int compel_cure_remote(struct parasite_ctl *ctl);
extern int compel_cure_local(struct parasite_ctl *ctl);
extern int compel_cure(struct parasite_ctl *ctl);

#define PARASITE_ARG_SIZE_MIN	( 1 << 12)

#define compel_parasite_args(ctl, type)					\
	({								\
	 	void *___ret;						\
		BUILD_BUG_ON(sizeof(type) > PARASITE_ARG_SIZE_MIN);	\
		___ret = compel_parasite_args_p(ctl);			\
	 	___ret;							\
	})

extern void *compel_parasite_args_p(struct parasite_ctl *ctl);
extern void *compel_parasite_args_s(struct parasite_ctl *ctl, int args_size);

extern int compel_execute_syscall(struct parasite_ctl *ctl,
		user_regs_struct_t *regs, const char *code_syscall);
extern int compel_run_in_thread(pid_t pid, unsigned int cmd,
					struct parasite_ctl *ctl,
					struct thread_ctx *octx);

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

extern int compel_stop_on_syscall(int tasks, int sys_nr,
		int sys_nr_compat, enum trace_flags trace);

extern int compel_stop_pie(pid_t pid, void *addr, enum trace_flags *tf, bool no_bp);

extern int compel_unmap(struct parasite_ctl *ctl, unsigned long addr);

extern int compel_mode_native(struct parasite_ctl *ctl);

extern k_rtsigset_t *compel_task_sigmask(struct parasite_ctl *ctl);

struct rt_sigframe;

typedef int (*open_proc_fn)(int pid, int mode, const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 3, 4)));

struct infect_ctx {
	int	*p_sock;

	/*
	 * Regs manipulation context.
	 */
	int (*save_regs)(void *, user_regs_struct_t *, user_fpregs_struct_t *);
	int (*make_sigframe)(void *, struct rt_sigframe *, struct rt_sigframe *, k_rtsigset_t *);
	void *regs_arg;

	unsigned long		syscall_ip;				/* entry point of infection */
	unsigned long		flags;			/* fine-tune (e.g. faults) */

	void (*child_handler)(int, siginfo_t *, void *);	/* hander for SIGCHLD deaths */

	open_proc_fn open_proc;
};

extern struct infect_ctx *compel_infect_ctx(struct parasite_ctl *);

#define INFECT_NO_MEMFD		0x1	/* don't use memfd() */
#define INFECT_FAIL_CONNECT	0x2	/* make parasite connect() fail */
#define INFECT_NO_BREAKPOINTS	0x4	/* no breakpoints in pie tracking */

typedef int (*save_regs_t)(void *, user_regs_struct_t *, user_fpregs_struct_t *);
extern int compel_get_task_regs(pid_t pid, user_regs_struct_t regs, save_regs_t, void *);

#endif
