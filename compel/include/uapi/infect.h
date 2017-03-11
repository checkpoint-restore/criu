#ifndef __COMPEL_INFECT_H__
#define __COMPEL_INFECT_H__

#include <stdbool.h>

#include <compel/asm/sigframe.h>
#include <compel/asm/infect-types.h>
#include <compel/ksigset.h>
#include <compel/handle-elf.h>
#include <compel/task-state.h>

#include "common/compiler.h"

#define PARASITE_START_AREA_MIN	(4096)

extern int compel_interrupt_task(int pid);

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

extern int compel_stop_task(int pid);
extern int compel_resume_task(pid_t pid, int orig_state, int state);

struct parasite_ctl;
struct parasite_thread_ctl;

extern struct parasite_ctl *compel_prepare(int pid);
extern struct parasite_ctl *compel_prepare_noctx(int pid);
extern int compel_infect(struct parasite_ctl *ctl, unsigned long nr_threads, unsigned long args_size);
extern struct parasite_thread_ctl *compel_prepare_thread(struct parasite_ctl *ctl, int pid);
extern void compel_release_thread(struct parasite_thread_ctl *);

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

extern int compel_syscall(struct parasite_ctl *ctl, int nr, long *ret,
		unsigned long arg1,
		unsigned long arg2,
		unsigned long arg3,
		unsigned long arg4,
		unsigned long arg5,
		unsigned long arg6);
extern int compel_run_in_thread(struct parasite_thread_ctl *tctl, unsigned int cmd);
extern int compel_run_at(struct parasite_ctl *ctl, unsigned long ip, user_regs_struct_t *ret_regs);

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
extern k_rtsigset_t *compel_thread_sigmask(struct parasite_thread_ctl *tctl);

struct rt_sigframe;

typedef int (*open_proc_fn)(int pid, int mode, const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 3, 4)));

struct infect_ctx {
	int	sock;

	/*
	 * Regs manipulation context.
	 */
	int (*save_regs)(void *, user_regs_struct_t *, user_fpregs_struct_t *);
	int (*make_sigframe)(void *, struct rt_sigframe *, struct rt_sigframe *, k_rtsigset_t *);
	void *regs_arg;

	unsigned long		task_size;
	unsigned long		syscall_ip;				/* entry point of infection */
	unsigned long		flags;			/* fine-tune (e.g. faults) */

	void (*child_handler)(int, siginfo_t *, void *);	/* hander for SIGCHLD deaths */
	struct sigaction	orig_handler;

	open_proc_fn open_proc;

	int			log_fd;	/* fd for parasite code to send messages to */
};

extern struct infect_ctx *compel_infect_ctx(struct parasite_ctl *);

#define INFECT_NO_MEMFD		0x1	/* don't use memfd() */
#define INFECT_FAIL_CONNECT	0x2	/* make parasite connect() fail */
#define INFECT_NO_BREAKPOINTS	0x4	/* no breakpoints in pie tracking */
#define INFECT_HAS_COMPAT_SIGRETURN 0x8

/*
 * There are several ways to describe a blob to compel
 * library. The simplest one derived from criu is to
 * provide it from .h files.
 */
#define COMPEL_BLOB_CHEADER	0x1

struct parasite_blob_desc {
	unsigned		parasite_type;
	union {
		struct {
			const void		*mem;
			size_t			bsize;
			size_t			nr_gotpcrel;
			unsigned long		parasite_ip_off;
			unsigned long		addr_cmd_off;
			unsigned long		addr_arg_off;
			compel_reloc_t		*relocs;
			unsigned int		nr_relocs;
		} hdr;
	};
};

extern struct parasite_blob_desc *compel_parasite_blob_desc(struct parasite_ctl *);

typedef int (*save_regs_t)(void *, user_regs_struct_t *, user_fpregs_struct_t *);
extern int compel_get_thread_regs(struct parasite_thread_ctl *, save_regs_t, void *);

extern void compel_relocs_apply(void *mem, void *vbase, size_t size, compel_reloc_t *elf_relocs, size_t nr_relocs);

extern unsigned long compel_task_size(void);

#endif
