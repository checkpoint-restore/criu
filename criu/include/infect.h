#ifndef __COMPEL_INFECT_H__
#define __COMPEL_INFECT_H__

#include "types.h"

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

/*
 * FIXME -- these should be mapped to pid.h's
 */

#define TASK_ALIVE		0x1
#define TASK_DEAD		0x2
#define TASK_STOPPED		0x3
#define TASK_ZOMBIE		0x6

struct parasite_ctl;
struct thread_ctx;

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

extern int compel_unmap(struct parasite_ctl *ctl, unsigned long addr);
#endif
