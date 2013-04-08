#include <string.h>
#include <unistd.h>
#include <elf.h>

#include "asm/processor-flags.h"
#include "asm/types.h"
#include "asm/fpu.h"

#include "compiler.h"
#include "ptrace.h"
#include "parasite-syscall.h"
#include "restorer.h"
#include "syscall.h"
#include "log.h"
#include "util.h"
#include "cpu.h"

#include "protobuf.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/creds.pb-c.h"

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

static int task_in_compat_mode(pid_t pid)
{
	unsigned long cs, ds;

	errno = 0;
	cs = ptrace(PTRACE_PEEKUSER, pid, offsetof(user_regs_struct_t, cs), 0);
	if (errno != 0) {
		pr_perror("Can't get CS register for %d", pid);
		return -1;
	}

	errno = 0;
	ds = ptrace(PTRACE_PEEKUSER, pid, offsetof(user_regs_struct_t, ds), 0);
	if (errno != 0) {
		pr_perror("Can't get DS register for %d", pid);
		return -1;
	}

	/* It's x86-32 or x32 */
	return cs != 0x33 || ds == 0x2b;
}

bool arch_can_dump_task(pid_t pid)
{
	if (task_in_compat_mode(pid)) {
		pr_err("Can't dump task %d running in 32-bit mode\n", pid);
		return false;
	}

	return true;
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
	err = __parasite_execute(ctl, ctl->pid.real, &regs);
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

	pr_info("Dumping GP/FPU registers for %d\n", pid);

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

int arch_alloc_thread_info(CoreEntry *core)
{
	ThreadInfoX86 *thread_info;
	UserX86RegsEntry *gpregs;
	UserX86FpregsEntry *fpregs;
	ThreadCoreEntry *thread_core;

	thread_info = xmalloc(sizeof(*thread_info));
	if (!thread_info)
		goto err;
	thread_info_x86__init(thread_info);
	core->thread_info = thread_info;

	thread_core = xmalloc(sizeof(*thread_core));
	if (!thread_core)
		goto err;
	thread_core_entry__init(thread_core);
	core->thread_core = thread_core;

	gpregs = xmalloc(sizeof(*gpregs));
	if (!gpregs)
		goto err;
	user_x86_regs_entry__init(gpregs);
	thread_info->gpregs = gpregs;

	if (cpu_has_feature(X86_FEATURE_FPU)) {
		fpregs = xmalloc(sizeof(*fpregs));
		if (!fpregs)
			goto err;
		user_x86_fpregs_entry__init(fpregs);
		thread_info->fpregs = fpregs;
		/* These are numbers from kernel */
		fpregs->n_st_space	= 32;
		fpregs->n_xmm_space	= 64;

		fpregs->st_space	= xzalloc(pb_repeated_size(fpregs, st_space));
		fpregs->xmm_space	= xzalloc(pb_repeated_size(fpregs, xmm_space));

		if (!fpregs->st_space || !fpregs->xmm_space)
			goto err;

		if (cpu_has_feature(X86_FEATURE_XSAVE)) {
			UserX86XsaveEntry *xsave;
			xsave = xmalloc(sizeof(*xsave));
			if (!xsave)
				goto err;
			user_x86_xsave_entry__init(xsave);
			thread_info->fpregs->xsave = xsave;

			xsave->n_ymmh_space = 64;
			xsave->ymmh_space = xzalloc(pb_repeated_size(xsave, ymmh_space));
			if (!xsave->ymmh_space)
				goto err;
		}
	}

	return 0;

err:
	return 1;
}

void arch_free_thread_info(CoreEntry *core)
{
	if (core->thread_info) {
		if (core->thread_info->fpregs) {
			if (core->thread_info->fpregs->xsave)
				xfree(core->thread_info->fpregs->xsave->ymmh_space);
			xfree(core->thread_info->fpregs->xsave);
			xfree(core->thread_info->fpregs->st_space);
			xfree(core->thread_info->fpregs->xmm_space);
			xfree(core->thread_info->fpregs->padding);
		}
		xfree(core->thread_info->gpregs);
		xfree(core->thread_info->fpregs);
		xfree(core->thread_info);
		core->thread_info = NULL;
	}
}

static bool valid_xsave_frame(CoreEntry *core)
{
	struct xsave_struct *x = NULL;

	if (core->thread_info->fpregs->n_st_space < ARRAY_SIZE(x->i387.st_space)) {
		pr_err("Corruption in FPU st_space area "
		       "(got %li but %li expected)\n",
		       (long)core->thread_info->fpregs->n_st_space,
		       (long)ARRAY_SIZE(x->i387.st_space));
		return false;
	}

	if (core->thread_info->fpregs->n_xmm_space < ARRAY_SIZE(x->i387.xmm_space)) {
		pr_err("Corruption in FPU xmm_space area "
		       "(got %li but %li expected)\n",
		       (long)core->thread_info->fpregs->n_st_space,
		       (long)ARRAY_SIZE(x->i387.xmm_space));
		return false;
	}

	if (cpu_has_feature(X86_FEATURE_XSAVE)) {
		if (!core->thread_info->fpregs->xsave) {
			pr_err("FPU xsave area is missing, "
			       "but host cpu requires it\n");
			return false;
		}
		if (core->thread_info->fpregs->xsave->n_ymmh_space < ARRAY_SIZE(x->ymmh.ymmh_space)) {
			pr_err("Corruption in FPU ymmh_space area "
			       "(got %li but %li expected)\n",
			       (long)core->thread_info->fpregs->xsave->n_ymmh_space,
			       (long)ARRAY_SIZE(x->ymmh.ymmh_space));
			return false;
		}
	} else {
		if (core->thread_info->fpregs->xsave) {
			pr_err("FPU xsave area present, "
			       "but host cpu doesn't support it\n");
			return false;
		}
		return true;
	}

	return true;
}

static void show_rt_xsave_frame(struct xsave_struct *x)
{
	struct fpx_sw_bytes *fpx = (void *)&x->i387.sw_reserved;
	struct xsave_hdr_struct *xsave_hdr = &x->xsave_hdr;
	struct i387_fxsave_struct *i387 = &x->i387;

	pr_debug("xsave runtime structure\n");
	pr_debug("-----------------------\n");

	pr_debug("cwd:%x swd:%x twd:%x fop:%x mxcsr:%x mxcsr_mask:%x\n",
		 (int)i387->cwd, (int)i387->swd, (int)i387->twd,
		 (int)i387->fop, (int)i387->mxcsr, (int)i387->mxcsr_mask);

	pr_debug("magic1:%x extended_size:%x xstate_bv:%lx xstate_size:%x\n",
		 fpx->magic1, fpx->extended_size, fpx->xstate_bv, fpx->xstate_size);

	pr_debug("xstate_bv: %lx\n", xsave_hdr->xstate_bv);

	pr_debug("-----------------------\n");
}

int sigreturn_prep_fpu_frame(struct thread_restore_args *args, CoreEntry *core)
{
	struct xsave_struct *x = &args->fpu_state.xsave;

	/*
	 * If no FPU information provided -- we're restoring
	 * old image which has no FPU support, or the dump simply
	 * has no FPU support at all.
	 */
	if (!core->thread_info->fpregs) {
		args->has_fpu = false;
		return 0;
	}

	if (!valid_xsave_frame(core))
		return -1;

	args->has_fpu = true;

#define assign_reg(dst, src, e)		do { dst.e = (__typeof__(dst.e))src->e; } while (0)
#define assign_array(dst, src, e)	memcpy(dst.e, (src)->e, sizeof(dst.e))

	assign_reg(x->i387, core->thread_info->fpregs, cwd);
	assign_reg(x->i387, core->thread_info->fpregs, swd);
	assign_reg(x->i387, core->thread_info->fpregs, twd);
	assign_reg(x->i387, core->thread_info->fpregs, fop);
	assign_reg(x->i387, core->thread_info->fpregs, rip);
	assign_reg(x->i387, core->thread_info->fpregs, rdp);
	assign_reg(x->i387, core->thread_info->fpregs, mxcsr);
	assign_reg(x->i387, core->thread_info->fpregs, mxcsr_mask);

	assign_array(x->i387, core->thread_info->fpregs, st_space);
	assign_array(x->i387, core->thread_info->fpregs, xmm_space);

	if (cpu_has_feature(X86_FEATURE_XSAVE)) {
		struct fpx_sw_bytes *fpx_sw = (void *)&x->i387.sw_reserved;
		void *magic2;

		x->xsave_hdr.xstate_bv	= XSTATE_FP | XSTATE_SSE | XSTATE_YMM;
		assign_array(x->ymmh, core->thread_info->fpregs->xsave, ymmh_space);

		fpx_sw->magic1		= FP_XSTATE_MAGIC1;
		fpx_sw->xstate_bv	= XSTATE_FP | XSTATE_SSE | XSTATE_YMM;
		fpx_sw->xstate_size	= sizeof(struct xsave_struct);
		fpx_sw->extended_size	= sizeof(struct xsave_struct) + FP_XSTATE_MAGIC2_SIZE;

		/*
		 * This should be at the end of xsave frame.
		 */
		magic2 = args->fpu_state.__pad + sizeof(struct xsave_struct);
		*(u32 *)magic2 = FP_XSTATE_MAGIC2;
	}

	show_rt_xsave_frame(x);

#undef assign_reg
#undef assign_array

	return 0;
}

void *mmap_seized(struct parasite_ctl *ctl,
		  void *addr, size_t length, int prot,
		  int flags, int fd, off_t offset)
{
	unsigned long map;
	int err;

	err = syscall_seized(ctl, __NR_mmap, &map,
			(unsigned long)addr, length, prot, flags, fd, offset);
	if (err < 0 || map > TASK_SIZE)
		map = 0;

	return (void *)map;
}
