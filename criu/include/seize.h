#ifndef __CR_SEIZE_H__
#define __CR_SEIZE_H__

#include <stdbool.h>
#include <sys/types.h>
#include <compel/ksigset.h>

/* Owned by the tracer, never by an API worker. Zero-initialize before use.
 * The caller must consume the TID's ptrace stop before restoring the context.
 */
struct criu_thread_context {
	pid_t tid;
	k_rtsigset_t sigmask;
	bool active;
	bool suspend_seccomp;
};

extern int criu_resume_thread_context(pid_t tid, struct criu_thread_context *ctx);
extern int criu_restore_thread_context(struct criu_thread_context *ctx);
/* Low-level primitive shared by the serial wrapper and the CPU ptrace tests. */
extern int criu_resume_thread_context_opts(pid_t tid, struct criu_thread_context *ctx,
					   unsigned long options, bool suspend_seccomp);

extern int collect_pstree(void);
extern int checkpoint_devices(void);
struct pstree_item;
extern void pstree_switch_state(struct pstree_item *root_item, int st);
extern const char *get_real_freezer_state(void);
extern bool alarm_timeouted(void);

extern char *task_comm_info(pid_t pid, char *comm, size_t size);
extern char *__task_comm_info(pid_t pid);
extern void set_compel_interrupt_only_mode(void);
extern int criu_resume_thread(pid_t tid);
extern int criu_restore_thread(pid_t tid);

#endif
