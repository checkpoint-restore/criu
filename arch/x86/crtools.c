#include <string.h>
#include <unistd.h>

#include "asm/types.h"
#include "compiler.h"
#include "ptrace.h"
#include "asm/processor-flags.h"
#include "protobuf.h"
#include "../protobuf/core.pb-c.h"
#include "../protobuf/creds.pb-c.h"
#include "parasite-syscall.h"
#include "syscall.h"
#include "log.h"
#include "util.h"
#include "cpu.h"
#include "fpu.h"
#include "elf.h"
#include "parasite-syscall.h"

/*
 * Injected syscall instruction
 */
const char code_syscall[] = {
	0x0f, 0x05,				/* syscall    */
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc	/* int 3, ... */
};

const int code_syscall_size = round_up(sizeof(code_syscall), sizeof(long));

static inline void __check_code_syscall(void)
{
	BUILD_BUG_ON(sizeof(code_syscall) != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

void parasite_setup_regs(unsigned long new_ip, user_regs_struct_t *regs)
{
	regs->ip = new_ip;

	/* Avoid end of syscall processing */
	regs->orig_ax = -1;

	/* Make sure flags are in known state */
	regs->flags &= ~(X86_EFLAGS_TF | X86_EFLAGS_DF | X86_EFLAGS_IF);
}

int syscall_seized(struct parasite_ctl *ctl, int nr, unsigned long *ret,
		unsigned long arg1,
		unsigned long arg2,
		unsigned long arg3,
		unsigned long arg4,
		unsigned long arg5,
		unsigned long arg6)
{
	user_regs_struct_t regs = ctl->regs_orig;
	int err;

	regs.ax  = (unsigned long)nr;
	regs.di  = arg1;
	regs.si  = arg2;
	regs.dx  = arg3;
	regs.r10 = arg4;
	regs.r8  = arg5;
	regs.r9  = arg6;

	parasite_setup_regs(ctl->syscall_ip, &regs);
	err = __parasite_execute(ctl, ctl->pid, &regs);
	if (err)
		return err;

	*ret = regs.ax;
	return 0;
}

int get_task_regs(pid_t pid, CoreEntry *core, const struct parasite_ctl *ctl)
{
	struct xsave_struct xsave	= {  };
	user_regs_struct_t regs		= {-1};

	struct iovec iov;
	int ret = -1;

	pr_info("Dumping GP/FPU registers ... ");

	if (ctl)
		regs = ctl->regs_orig;
	else {
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs)) {
			pr_err("Can't obtain GP registers for %d\n", pid);
			goto err;
		}
	}

	/* Did we come from a system call? */
	if ((int)regs.orig_ax >= 0) {
		/* Restart the system call */
		switch ((long)(int)regs.ax) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			regs.ax = regs.orig_ax;
			regs.ip -= 2;
			break;
		case -ERESTART_RESTARTBLOCK:
			regs.ax = __NR_restart_syscall;
			regs.ip -= 2;
			break;
		}
	}

#define assign_reg(dst, src, e)		do { dst->e = (__typeof__(dst->e))src.e; } while (0)
#define assign_array(dst, src, e)	memcpy(dst->e, &src.e, sizeof(src.e))

	assign_reg(core->thread_info->gpregs, regs, r15);
	assign_reg(core->thread_info->gpregs, regs, r14);
	assign_reg(core->thread_info->gpregs, regs, r13);
	assign_reg(core->thread_info->gpregs, regs, r12);
	assign_reg(core->thread_info->gpregs, regs, bp);
	assign_reg(core->thread_info->gpregs, regs, bx);
	assign_reg(core->thread_info->gpregs, regs, r11);
	assign_reg(core->thread_info->gpregs, regs, r10);
	assign_reg(core->thread_info->gpregs, regs, r9);
	assign_reg(core->thread_info->gpregs, regs, r8);
	assign_reg(core->thread_info->gpregs, regs, ax);
	assign_reg(core->thread_info->gpregs, regs, cx);
	assign_reg(core->thread_info->gpregs, regs, dx);
	assign_reg(core->thread_info->gpregs, regs, si);
	assign_reg(core->thread_info->gpregs, regs, di);
	assign_reg(core->thread_info->gpregs, regs, orig_ax);
	assign_reg(core->thread_info->gpregs, regs, ip);
	assign_reg(core->thread_info->gpregs, regs, cs);
	assign_reg(core->thread_info->gpregs, regs, flags);
	assign_reg(core->thread_info->gpregs, regs, sp);
	assign_reg(core->thread_info->gpregs, regs, ss);
	assign_reg(core->thread_info->gpregs, regs, fs_base);
	assign_reg(core->thread_info->gpregs, regs, gs_base);
	assign_reg(core->thread_info->gpregs, regs, ds);
	assign_reg(core->thread_info->gpregs, regs, es);
	assign_reg(core->thread_info->gpregs, regs, fs);
	assign_reg(core->thread_info->gpregs, regs, gs);

#ifndef PTRACE_GETREGSET
# define PTRACE_GETREGSET 0x4204
#endif

	if (!cpu_has_feature(X86_FEATURE_FPU))
		goto out;

	/*
	 * FPU fetched either via fxsave or via xsave,
	 * thus decode it accrodingly.
	 */

	if (cpu_has_feature(X86_FEATURE_XSAVE)) {
		iov.iov_base = &xsave;
		iov.iov_len = sizeof(xsave);

		if (ptrace(PTRACE_GETREGSET, pid, (unsigned int)NT_X86_XSTATE, &iov) < 0) {
			pr_err("Can't obtain FPU registers for %d\n", pid);
			goto err;
		}
	} else {
		if (ptrace(PTRACE_GETFPREGS, pid, NULL, &xsave)) {
			pr_err("Can't obtain FPU registers for %d\n", pid);
			goto err;
		}
	}

	assign_reg(core->thread_info->fpregs, xsave.i387, cwd);
	assign_reg(core->thread_info->fpregs, xsave.i387, swd);
	assign_reg(core->thread_info->fpregs, xsave.i387, twd);
	assign_reg(core->thread_info->fpregs, xsave.i387, fop);
	assign_reg(core->thread_info->fpregs, xsave.i387, rip);
	assign_reg(core->thread_info->fpregs, xsave.i387, rdp);
	assign_reg(core->thread_info->fpregs, xsave.i387, mxcsr);
	assign_reg(core->thread_info->fpregs, xsave.i387, mxcsr_mask);

	/* Make sure we have enough space */
	BUG_ON(core->thread_info->fpregs->n_st_space != ARRAY_SIZE(xsave.i387.st_space));
	BUG_ON(core->thread_info->fpregs->n_xmm_space != ARRAY_SIZE(xsave.i387.xmm_space));

	assign_array(core->thread_info->fpregs, xsave.i387, st_space);
	assign_array(core->thread_info->fpregs, xsave.i387, xmm_space);

	if (cpu_has_feature(X86_FEATURE_XSAVE)) {
		BUG_ON(core->thread_info->fpregs->xsave->n_ymmh_space != ARRAY_SIZE(xsave.ymmh.ymmh_space));

		assign_reg(core->thread_info->fpregs->xsave, xsave.xsave_hdr, xstate_bv);
		assign_array(core->thread_info->fpregs->xsave, xsave.ymmh, ymmh_space);
	}

#undef assign_reg
#undef assign_array

out:
	ret = 0;

err:
	return ret;
}
