#ifndef __COMPEL_INFECT_PRIV_H__
#define __COMPEL_INFECT_PRIV_H__

#include <stdbool.h>

#define BUILTIN_SYSCALL_SIZE 8

struct thread_ctx {
	k_rtsigset_t sigmask;
	user_regs_struct_t regs;
#ifdef ARCH_HAS_PTRACE_GET_THREAD_AREA
	tls_t tls;
#endif
	user_fpregs_struct_t ext_regs;
};

/* parasite control block */
struct parasite_ctl {
	int rpid; /* Real pid of the victim */
	void *remote_map;
	void *local_map;
	void *sigreturn_addr; /* A place for the breakpoint */
	unsigned long map_length;

	struct infect_ctx ictx;

	/* thread leader data */
	bool daemonized;

	struct thread_ctx orig;

	void *rstack; /* thread leader stack*/
	struct rt_sigframe *sigframe;
	struct rt_sigframe *rsigframe; /* address in a parasite */

	void *r_thread_stack; /* stack for non-leader threads */

	unsigned long parasite_ip; /* service routine start ip */

	unsigned int *cmd; /* address for command */
	void *args; /* address for arguments */
	unsigned long args_size;
	int tsock; /* transport socket for transferring fds */

	struct parasite_blob_desc pblob;
};

struct parasite_thread_ctl {
	int tid;
	struct parasite_ctl *ctl;
	struct thread_ctx th;
};

#define MEMFD_FNAME    "CRIUMFD"
#define MEMFD_FNAME_SZ sizeof(MEMFD_FNAME)

struct ctl_msg;
int parasite_wait_ack(int sockfd, unsigned int cmd, struct ctl_msg *m);

extern void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs);
extern void *remote_mmap(struct parasite_ctl *ctl, void *addr, size_t length, int prot, int flags, int fd,
			 off_t offset);
extern bool arch_can_dump_task(struct parasite_ctl *ctl);
/*
 * @regs:	general purpose registers
 * @ext_regs:	extended register set (fpu/mmx/sse/etc)
 *		for task that is NULL, restored by sigframe on rt_sigreturn()
 * @save:	callback to dump all info
 * @flags:	see INFECT_* in infect_ctx::flags
 * @pid:	mystery
 */
extern int compel_get_task_regs(pid_t pid, user_regs_struct_t *regs, user_fpregs_struct_t *ext_regs, save_regs_t save,
				void *arg, unsigned long flags);
extern int compel_set_task_ext_regs(pid_t pid, user_fpregs_struct_t *ext_regs);
extern int arch_fetch_sas(struct parasite_ctl *ctl, struct rt_sigframe *s);
extern int sigreturn_prep_regs_plain(struct rt_sigframe *sigframe, user_regs_struct_t *regs,
				     user_fpregs_struct_t *fpregs);
extern int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe);
extern int compel_execute_syscall(struct parasite_ctl *ctl, user_regs_struct_t *regs, const char *code_syscall);
#endif
