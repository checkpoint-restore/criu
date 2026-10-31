#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <compel/ptrace.h>
#include "criu-log.h"
#include "seize.h"

int criu_resume_thread_context_opts(pid_t tid, struct criu_thread_context *ctx,
				    unsigned long options, bool suspend_seccomp)
{
	k_rtsigset_t block;
	bool options_set = false;

	if (ctx->active || tid <= 0) {
		pr_err("Invalid resume context for tid %d (active %d)\n", tid, ctx->active);
		return -EINVAL;
	}
	ctx->tid = 0;
	if (ptrace(PTRACE_GETSIGMASK, tid, sizeof(ctx->sigmask), &ctx->sigmask))
		return -errno;
	ksigfillset(&block);
	ksigdelset(&block, SIGTRAP);
	if (ptrace(PTRACE_SETSIGMASK, tid, sizeof(block), &block)) {
		pr_perror("Failed to block signals on restore tid %d", tid);
		return -1;
	}
	/* The restore thread must run with its seccomp filter enabled. */
	if (ptrace(PTRACE_SETOPTIONS, tid, NULL, options)) {
		pr_perror("Could not set ptrace options on restore tid %d", tid);
		goto unwind;
	}
	options_set = true;
	if (ptrace(PTRACE_CONT, tid, NULL, 0)) {
		pr_perror("Could not resume restore tid %d", tid);
		goto unwind;
	}
	ctx->tid = tid;
	ctx->suspend_seccomp = suspend_seccomp;
	ctx->active = true;
	return 0;
unwind:
	if (options_set && suspend_seccomp && ptrace_suspend_seccomp(tid) < 0)
		pr_err("Unable to restore ptrace options for restore tid %d\n", tid);
	if (ptrace(PTRACE_SETSIGMASK, tid, sizeof(ctx->sigmask), &ctx->sigmask))
		pr_perror("Unable to restore signal mask for restore tid %d", tid);
	return -1;
}

int __attribute__((used)) criu_restore_thread_context(struct criu_thread_context *ctx)
{
	int ret = 0;

	if (!ctx->active) {
		pr_err("Attempt to restore inactive thread context\n");
		return -EINVAL;
	}
	if (ctx->suspend_seccomp && ptrace_suspend_seccomp(ctx->tid) < 0)
		ret = -1;
	if (ptrace(PTRACE_SETSIGMASK, ctx->tid, sizeof(ctx->sigmask), &ctx->sigmask)) {
		pr_perror("Unable to restore original sigmask to restore tid %d", ctx->tid);
		ret = -1;
	}
	ctx->active = false;
	ctx->tid = 0;
	return ret;
}
