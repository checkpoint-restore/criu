#ifndef __CR_PARASITE_SYSCALL_H__
#define __CR_PARASITE_SYSCALL_H__

#include "pid.h"
#include "common/list.h"
#include "config.h"
#include "asm/parasite-syscall.h"

#define BUILTIN_SYSCALL_SIZE	8

struct parasite_dump_thread;
struct parasite_dump_misc;
struct parasite_drain_fd;
struct vm_area_list;
struct pstree_item;
struct _CredsEntry;
struct _CoreEntry;
struct list_head;
struct cr_imgset;
struct fd_opts;
struct pid;
struct parasite_dump_cgroup_args;
struct rt_sigframe;

struct thread_ctx {
	k_rtsigset_t		sigmask;
	user_regs_struct_t	regs;
};

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
};

#define INFECT_NO_MEMFD		0x1	/* don't use memfd() */
#define INFECT_FAIL_CONNECT	0x2	/* make parasite connect() fail */

struct parasite_ctl;

extern int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct cr_imgset *cr_imgset);
extern int parasite_dump_itimers_seized(struct parasite_ctl *ctl, struct pstree_item *);

struct proc_posix_timers_stat;
extern int parasite_dump_posix_timers_seized(struct proc_posix_timers_stat *proc_args,
		struct parasite_ctl *ctl, struct pstree_item *);

#define parasite_args(ctl, type)					\
	({								\
	 	void *___ret;						\
		BUILD_BUG_ON(sizeof(type) > PARASITE_ARG_SIZE_MIN);	\
		___ret = parasite_args_p(ctl);				\
	 	___ret;							\
	})

extern void *parasite_args_p(struct parasite_ctl *ctl);
extern void *parasite_args_s(struct parasite_ctl *ctl, int args_size);
extern int parasite_send_fd(struct parasite_ctl *ctl, int fd);

/*
 * Execute a command in parasite when it's in daemon mode.
 * The __-ed version is asyncronous (doesn't wait for ack).
 */
extern int parasite_execute_daemon(unsigned int cmd, struct parasite_ctl *ctl);
extern int __parasite_execute_daemon(unsigned int cmd, struct parasite_ctl *ctl);

extern int __parasite_wait_daemon_ack(unsigned int cmd,
					      struct parasite_ctl *ctl);

extern int parasite_dump_misc_seized(struct parasite_ctl *ctl, struct parasite_dump_misc *misc);
extern int parasite_dump_creds(struct parasite_ctl *ctl, struct _CredsEntry *ce);
extern int parasite_dump_thread_leader_seized(struct parasite_ctl *ctl, int pid, struct _CoreEntry *core);
extern int parasite_dump_thread_seized(struct parasite_ctl *ctl, int id,
					struct pid *tid, struct _CoreEntry *core);
extern int dump_thread_core(int pid, CoreEntry *core, bool native,
					const void *dump_thread);

extern int parasite_drain_fds_seized(struct parasite_ctl *ctl,
					struct parasite_drain_fd *dfds, int nr_fds, int off,
					int *lfds, struct fd_opts *flags);
extern int parasite_get_proc_fd_seized(struct parasite_ctl *ctl);

extern int parasite_cure_remote(struct parasite_ctl *ctl);
extern int parasite_cure_local(struct parasite_ctl *ctl);
extern int parasite_cure_seized(struct parasite_ctl *ctl);
extern struct parasite_ctl *parasite_infect_seized(pid_t pid,
						   struct pstree_item *item,
						   struct vm_area_list *vma_area_list);
extern void parasite_ensure_args_size(unsigned long sz);
extern unsigned long get_exec_start(struct vm_area_list *);
extern struct parasite_ctl *parasite_prep_ctl(pid_t pid);
extern int parasite_map_exchange(struct parasite_ctl *ctl, unsigned long size);

extern int parasite_dump_cgroup(struct parasite_ctl *ctl, struct parasite_dump_cgroup_args *cgroup);

extern struct parasite_tty_args *parasite_dump_tty(struct parasite_ctl *ctl, int fd, int type);

extern int parasite_init_threads_seized(struct parasite_ctl *ctl, struct pstree_item *item);
extern int parasite_fini_threads_seized(struct parasite_ctl *ctl);

extern int syscall_seized(struct parasite_ctl *ctl, int nr, unsigned long *ret,
			  unsigned long arg1, unsigned long arg2,
			  unsigned long arg3, unsigned long arg4,
			  unsigned long arg5, unsigned long arg6);

extern int __parasite_execute_syscall(struct parasite_ctl *ctl,
		user_regs_struct_t *regs, const char *code_syscall);
extern bool arch_can_dump_task(struct parasite_ctl *ctl);
extern bool seized_native(struct parasite_ctl *ctl);

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

extern int parasite_stop_daemon(struct parasite_ctl *ctl);
extern int parasite_stop_on_syscall(int tasks, int sys_nr,
		int sys_nr_compat, enum trace_flags trace);
extern int parasite_unmap(struct parasite_ctl *ctl, unsigned long addr);
extern int ptrace_stop_pie(pid_t pid, void *addr, enum trace_flags *tf);

#endif /* __CR_PARASITE_SYSCALL_H__ */
