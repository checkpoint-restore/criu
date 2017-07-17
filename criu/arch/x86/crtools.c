#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/auxv.h>
#include <sys/wait.h>

#include "types.h"
#include "log.h"
#include "asm/compat.h"
#include "asm/parasite-syscall.h"
#include "asm/restorer.h"
#include <compel/asm/fpu.h>
#include "asm/dump.h"

#include "cr_options.h"
#include "common/compiler.h"
#include "restorer.h"
#include "parasite-syscall.h"
#include "util.h"
#include "cpu.h"
#include <compel/plugins/std/syscall-codes.h>
#include "kerndat.h"
#include <compel/compel.h>

#include "protobuf.h"
#include "images/core.pb-c.h"
#include "images/creds.pb-c.h"

int kdat_can_map_vdso(void)
{
	pid_t child;
	int stat;

	/*
	 * Running under fork so if vdso_64 is disabled - don't create
	 * it for criu accidentally.
	 */
	child = fork();
	if (child < 0)
		return -1;

	if (child == 0) {
		int ret;

		ret = syscall(SYS_arch_prctl, ARCH_MAP_VDSO_32, 0);
		if (ret == 0)
			exit(1);
		/*
		 * Mapping vDSO while have not unmap it yet:
		 * this is restricted by API if ARCH_MAP_VDSO_* is supported.
		 */
		if (ret == -1 && errno == EEXIST)
			exit(1);
		exit(0);
	}

	if (waitpid(child, &stat, 0) != child) {
		pr_err("Failed to wait for arch_prctl() test");
		kill(child, SIGKILL);
		return -1;
	}

	if (!WIFEXITED(stat))
		return -1;

	return WEXITSTATUS(stat);

}

#ifdef CONFIG_COMPAT
void *mmap_ia32(void *addr, size_t len, int prot,
		int flags, int fildes, off_t off)
{
	struct syscall_args32 s;

	s.nr    = __NR32_mmap2;
	s.arg0  = (uint32_t)(uintptr_t)addr;
	s.arg1  = (uint32_t)len;
	s.arg2  = prot;
	s.arg3  = flags;
	s.arg4  = fildes;
	s.arg5  = (uint32_t)off;

	do_full_int80(&s);

	return (void *)(uintptr_t)s.nr;
}

/*
 * The idea of the test:
 * From kernel's top-down allocator we assume here that
 * 1. A = mmap(0, ...); munmap(A);
 * 2. B = mmap(0, ...);
 * results in A == B.
 * ...but if we have 32-bit mmap() bug, then A will have only lower
 * 4 bytes of 64-bit address allocated with mmap().
 * That means, that the next mmap() will return B != A
 * (as munmap(A) hasn't really unmapped A mapping).
 *
 * As mapping with lower 4 bytes of A may really exist, we run
 * this test under fork().
 *
 * Another approach to test bug's presence would be to parse
 * /proc/self/maps before and after 32-bit mmap(), but that would
 * be soo slow.
 */
static void mmap_bug_test(void)
{
	void *map1, *map2;
	int err;

	map1 = mmap_ia32(0, PAGE_SIZE, PROT_NONE, MAP_ANON|MAP_PRIVATE, -1, 0);
	/* 32-bit error, not sign-extended - can't use IS_ERR_VALUE() here */
	err = (uintptr_t)map1 % PAGE_SIZE;
	if (err) {
		pr_err("ia32 mmap() failed: %d\n", err);
		exit(1);
	}

	if (munmap(map1, PAGE_SIZE)) {
		pr_err("Failed to unmap() 32-bit mapping: %m\n");
		exit(1);
	}

	map2 = mmap_ia32(0, PAGE_SIZE, PROT_NONE, MAP_ANON|MAP_PRIVATE, -1, 0);
	err = (uintptr_t)map2 % PAGE_SIZE;
	if (err) {
		pr_err("ia32 mmap() failed: %d\n", err);
		exit(1);
	}

	if (map1 != map2)
		exit(1);
	exit(0);
}

/*
 * Pre v4.12 kernels have a bug: for a process started as 64-bit
 * 32-bit mmap() may return 8 byte pointer.
 * Which is fatal for us: after 32-bit C/R a task will map 64-bit
 * addresses, cut upper 4 bytes and try to use lower 4 bytes.
 * This is a check if the bug was fixed in the kernel.
 */
static int has_32bit_mmap_bug(void)
{
	pid_t child = fork();
	int stat;

	if (child == 0)
		mmap_bug_test();

	if (waitpid(child, &stat, 0) != child) {
		pr_err("Failed to wait for mmap test");
		kill(child, SIGKILL);
		return -1;
	}

	if (!WIFEXITED(stat) || WEXITSTATUS(stat) != 0)
		return 1;
	return 0;
}

int kdat_compatible_cr(void)
{
	if (!kdat.can_map_vdso)
		return 0;

	if (has_32bit_mmap_bug())
		return 0;

	return 1;
}
#else /* !CONFIG_COMPAT */
int kdat_compatible_cr(void)
{
	return 0;
}
#endif

int save_task_regs(void *x, user_regs_struct_t *regs, user_fpregs_struct_t *fpregs)
{
	CoreEntry *core = x;
	UserX86RegsEntry *gpregs	= core->thread_info->gpregs;

#define assign_reg(dst, src, e)		do { dst->e = (__typeof__(dst->e))src.e; } while (0)
#define assign_array(dst, src, e)	memcpy(dst->e, &src.e, sizeof(src.e))

	if (user_regs_native(regs)) {
		assign_reg(gpregs, regs->native, r15);
		assign_reg(gpregs, regs->native, r14);
		assign_reg(gpregs, regs->native, r13);
		assign_reg(gpregs, regs->native, r12);
		assign_reg(gpregs, regs->native, bp);
		assign_reg(gpregs, regs->native, bx);
		assign_reg(gpregs, regs->native, r11);
		assign_reg(gpregs, regs->native, r10);
		assign_reg(gpregs, regs->native, r9);
		assign_reg(gpregs, regs->native, r8);
		assign_reg(gpregs, regs->native, ax);
		assign_reg(gpregs, regs->native, cx);
		assign_reg(gpregs, regs->native, dx);
		assign_reg(gpregs, regs->native, si);
		assign_reg(gpregs, regs->native, di);
		assign_reg(gpregs, regs->native, orig_ax);
		assign_reg(gpregs, regs->native, ip);
		assign_reg(gpregs, regs->native, cs);
		assign_reg(gpregs, regs->native, flags);
		assign_reg(gpregs, regs->native, sp);
		assign_reg(gpregs, regs->native, ss);
		assign_reg(gpregs, regs->native, fs_base);
		assign_reg(gpregs, regs->native, gs_base);
		assign_reg(gpregs, regs->native, ds);
		assign_reg(gpregs, regs->native, es);
		assign_reg(gpregs, regs->native, fs);
		assign_reg(gpregs, regs->native, gs);
		gpregs->mode = USER_X86_REGS_MODE__NATIVE;
	} else {
		assign_reg(gpregs, regs->compat, bx);
		assign_reg(gpregs, regs->compat, cx);
		assign_reg(gpregs, regs->compat, dx);
		assign_reg(gpregs, regs->compat, si);
		assign_reg(gpregs, regs->compat, di);
		assign_reg(gpregs, regs->compat, bp);
		assign_reg(gpregs, regs->compat, ax);
		assign_reg(gpregs, regs->compat, ds);
		assign_reg(gpregs, regs->compat, es);
		assign_reg(gpregs, regs->compat, fs);
		assign_reg(gpregs, regs->compat, gs);
		assign_reg(gpregs, regs->compat, orig_ax);
		assign_reg(gpregs, regs->compat, ip);
		assign_reg(gpregs, regs->compat, cs);
		assign_reg(gpregs, regs->compat, flags);
		assign_reg(gpregs, regs->compat, sp);
		assign_reg(gpregs, regs->compat, ss);
		gpregs->mode = USER_X86_REGS_MODE__COMPAT;
	}
	gpregs->has_mode = true;

	if (!fpregs)
		return 0;

	assign_reg(core->thread_info->fpregs, fpregs->i387, cwd);
	assign_reg(core->thread_info->fpregs, fpregs->i387, swd);
	assign_reg(core->thread_info->fpregs, fpregs->i387, twd);
	assign_reg(core->thread_info->fpregs, fpregs->i387, fop);
	assign_reg(core->thread_info->fpregs, fpregs->i387, rip);
	assign_reg(core->thread_info->fpregs, fpregs->i387, rdp);
	assign_reg(core->thread_info->fpregs, fpregs->i387, mxcsr);
	assign_reg(core->thread_info->fpregs, fpregs->i387, mxcsr_mask);

	/* Make sure we have enough space */
	BUG_ON(core->thread_info->fpregs->n_st_space != ARRAY_SIZE(fpregs->i387.st_space));
	BUG_ON(core->thread_info->fpregs->n_xmm_space != ARRAY_SIZE(fpregs->i387.xmm_space));

	assign_array(core->thread_info->fpregs, fpregs->i387, st_space);
	assign_array(core->thread_info->fpregs, fpregs->i387, xmm_space);

	if (compel_cpu_has_feature(X86_FEATURE_OSXSAVE)) {
		BUG_ON(core->thread_info->fpregs->xsave->n_ymmh_space != ARRAY_SIZE(fpregs->ymmh.ymmh_space));

		assign_reg(core->thread_info->fpregs->xsave, fpregs->xsave_hdr, xstate_bv);
		assign_array(core->thread_info->fpregs->xsave, fpregs->ymmh, ymmh_space);
	}

#undef assign_reg
#undef assign_array

	return 0;
}

static void alloc_tls(ThreadInfoX86 *ti, void **mempool)
{
	int i;

	ti->tls = xptr_pull_s(mempool, GDT_ENTRY_TLS_NUM*sizeof(UserDescT*));
	ti->n_tls = GDT_ENTRY_TLS_NUM;
	for (i = 0; i < GDT_ENTRY_TLS_NUM; i++) {
		ti->tls[i] = xptr_pull(mempool, UserDescT);
		user_desc_t__init(ti->tls[i]);
	}
}

int arch_alloc_thread_info(CoreEntry *core)
{
	size_t sz;
	bool with_fpu, with_xsave = false;
	void *m;
	ThreadInfoX86 *ti = NULL;


	with_fpu = compel_cpu_has_feature(X86_FEATURE_FPU);

	sz = sizeof(ThreadInfoX86) + sizeof(UserX86RegsEntry) +
		GDT_ENTRY_TLS_NUM*sizeof(UserDescT) +
		GDT_ENTRY_TLS_NUM*sizeof(UserDescT*);
	if (with_fpu) {
		sz += sizeof(UserX86FpregsEntry);
		with_xsave = compel_cpu_has_feature(X86_FEATURE_OSXSAVE);
		if (with_xsave)
			sz += sizeof(UserX86XsaveEntry);
	}

	m = xmalloc(sz);
	if (!m)
		return -1;

	ti = core->thread_info = xptr_pull(&m, ThreadInfoX86);
	thread_info_x86__init(ti);
	ti->gpregs = xptr_pull(&m, UserX86RegsEntry);
	user_x86_regs_entry__init(ti->gpregs);
	alloc_tls(ti, &m);

	if (with_fpu) {
		UserX86FpregsEntry *fpregs;

		fpregs = ti->fpregs = xptr_pull(&m, UserX86FpregsEntry);
		user_x86_fpregs_entry__init(fpregs);

		/* These are numbers from kernel */
		fpregs->n_st_space	= 32;
		fpregs->n_xmm_space	= 64;

		fpregs->st_space	= xzalloc(pb_repeated_size(fpregs, st_space));
		fpregs->xmm_space	= xzalloc(pb_repeated_size(fpregs, xmm_space));

		if (!fpregs->st_space || !fpregs->xmm_space)
			goto err;

		if (with_xsave) {
			UserX86XsaveEntry *xsave;

			xsave = fpregs->xsave = xptr_pull(&m, UserX86XsaveEntry);
			user_x86_xsave_entry__init(xsave);

			xsave->n_ymmh_space = 64;
			xsave->ymmh_space = xzalloc(pb_repeated_size(xsave, ymmh_space));
			if (!xsave->ymmh_space)
				goto err;
		}
	}

	return 0;
err:
	return -1;
}

void arch_free_thread_info(CoreEntry *core)
{
	if (!core->thread_info)
		return;

	if (core->thread_info->fpregs->xsave)
		xfree(core->thread_info->fpregs->xsave->ymmh_space);
	xfree(core->thread_info->fpregs->st_space);
	xfree(core->thread_info->fpregs->xmm_space);
	xfree(core->thread_info);
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

	if (compel_cpu_has_feature(X86_FEATURE_OSXSAVE)) {
		if (core->thread_info->fpregs->xsave &&
		    core->thread_info->fpregs->xsave->n_ymmh_space < ARRAY_SIZE(x->ymmh.ymmh_space)) {
			pr_err("Corruption in FPU ymmh_space area "
			       "(got %li but %li expected)\n",
			       (long)core->thread_info->fpregs->xsave->n_ymmh_space,
			       (long)ARRAY_SIZE(x->ymmh.ymmh_space));
			return false;
		}
	} else {
		/*
		 * If the image has xsave area present then CPU we're restoring
		 * on must have X86_FEATURE_OSXSAVE feature until explicitly
		 * stated in options.
		 */
		if (core->thread_info->fpregs->xsave) {
			if (opts.cpu_cap & CPU_CAP_FPU) {
				pr_err("FPU xsave area present, "
				       "but host cpu doesn't support it\n");
				return false;
			} else
				pr_warn_once("FPU is about to restore ignoring ymm state!\n");
		}
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
		 fpx->magic1, fpx->extended_size, (long)fpx->xstate_bv, fpx->xstate_size);

	pr_debug("xstate_bv: %lx\n", (long)xsave_hdr->xstate_bv);

	pr_debug("-----------------------\n");
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core)
{
	fpu_state_t *fpu_state = core_is_compat(core) ?
		&sigframe->compat.fpu_state :
		&sigframe->native.fpu_state;
	struct xsave_struct *x = core_is_compat(core) ?
		(void *)&fpu_state->fpu_state_ia32.xsave :
		(void *)&fpu_state->fpu_state_64.xsave;

	/*
	 * If no FPU information provided -- we're restoring
	 * old image which has no FPU support, or the dump simply
	 * has no FPU support at all.
	 */
	if (!core->thread_info->fpregs) {
		fpu_state->has_fpu = false;
		return 0;
	}

	if (!valid_xsave_frame(core))
		return -1;

	fpu_state->has_fpu = true;

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

	if (core_is_compat(core))
		compel_convert_from_fxsr(&fpu_state->fpu_state_ia32.fregs_state.i387_ia32,
					 &fpu_state->fpu_state_ia32.xsave.i387);

	if (compel_cpu_has_feature(X86_FEATURE_OSXSAVE)) {
		struct fpx_sw_bytes *fpx_sw = (void *)&x->i387.sw_reserved;
		void *magic2;

		x->xsave_hdr.xstate_bv	= XSTATE_FP | XSTATE_SSE | XSTATE_YMM;

		/*
		 * fpregs->xsave pointer might not present on image so we
		 * simply clear out all ymm registers.
		 */
		if (core->thread_info->fpregs->xsave)
			assign_array(x->ymmh, core->thread_info->fpregs->xsave, ymmh_space);

		fpx_sw->magic1		= FP_XSTATE_MAGIC1;
		fpx_sw->xstate_bv	= XSTATE_FP | XSTATE_SSE | XSTATE_YMM;
		fpx_sw->xstate_size	= sizeof(struct xsave_struct);
		fpx_sw->extended_size	= sizeof(struct xsave_struct) + FP_XSTATE_MAGIC2_SIZE;

		/*
		 * This should be at the end of xsave frame.
		 */
		magic2 = (void *)x + sizeof(struct xsave_struct);
		*(u32 *)magic2 = FP_XSTATE_MAGIC2;
	}

	show_rt_xsave_frame(x);

#undef assign_reg
#undef assign_array

	return 0;
}

#define CPREG32(d)	f->compat.uc.uc_mcontext.d = r->d
static void restore_compat_gpregs(struct rt_sigframe *f, UserX86RegsEntry *r)
{
	CPREG32(gs);
	CPREG32(fs);
	CPREG32(es);
	CPREG32(ds);

	CPREG32(di); CPREG32(si); CPREG32(bp); CPREG32(sp); CPREG32(bx);
	CPREG32(dx); CPREG32(cx); CPREG32(ip); CPREG32(ax);
	CPREG32(cs);
	CPREG32(ss);
	CPREG32(flags);

	f->is_native = false;
}
#undef CPREG32

#define CPREG64(d, s)	f->native.uc.uc_mcontext.d = r->s
static void restore_native_gpregs(struct rt_sigframe *f, UserX86RegsEntry *r)
{
	CPREG64(rdi, di);
	CPREG64(rsi, si);
	CPREG64(rbp, bp);
	CPREG64(rsp, sp);
	CPREG64(rbx, bx);
	CPREG64(rdx, dx);
	CPREG64(rcx, cx);
	CPREG64(rip, ip);
	CPREG64(rax, ax);

	CPREG64(r8, r8);
	CPREG64(r9, r9);
	CPREG64(r10, r10);
	CPREG64(r11, r11);
	CPREG64(r12, r12);
	CPREG64(r13, r13);
	CPREG64(r14, r14);
	CPREG64(r15, r15);

	CPREG64(cs, cs);

	CPREG64(eflags, flags);

	f->is_native = true;
}
#undef CPREG64

int restore_gpregs(struct rt_sigframe *f, UserX86RegsEntry *r)
{
	switch (r->mode) {
		case USER_X86_REGS_MODE__NATIVE:
			restore_native_gpregs(f, r);
			break;
		case USER_X86_REGS_MODE__COMPAT:
			restore_compat_gpregs(f, r);
			break;
		default:
			pr_err("Can't prepare rt_sigframe: registers mode corrupted (%d)\n", r->mode);
			return -1;
	}
	return 0;
}

static int get_robust_list32(pid_t pid, uintptr_t head, uintptr_t len)
{
	struct syscall_args32 s = {
		.nr	= __NR32_get_robust_list,
		.arg0	= pid,
		.arg1	= (uint32_t)head,
		.arg2	= (uint32_t)len,
	};

	do_full_int80(&s);
	return (int)s.nr;
}

static int set_robust_list32(uint32_t head, uint32_t len)
{
	struct syscall_args32 s = {
		.nr	= __NR32_set_robust_list,
		.arg0	= head,
		.arg1	= len,
	};

	do_full_int80(&s);
	return (int)s.nr;
}

int get_task_futex_robust_list_compat(pid_t pid, ThreadCoreEntry *info)
{
	void *mmap32;
	int ret = -1;

	mmap32 = alloc_compat_syscall_stack();
	if (!mmap32)
		return -1;

	ret = get_robust_list32(pid, (uintptr_t)mmap32, (uintptr_t)mmap32 + 4);

	if (ret == -ENOSYS) {
		/* Check native get_task_futex_robust_list() for details. */
		if (set_robust_list32(0, 0) == (uint32_t)-ENOSYS) {
			info->futex_rla		= 0;
			info->futex_rla_len	= 0;
			ret = 0;
		}
	} else if (ret == 0) {
		uint32_t *arg1		= (uint32_t*)mmap32;

		info->futex_rla		= *arg1;
		info->futex_rla_len	= *(arg1 + 1);
		ret = 0;
	}


	free_compat_syscall_stack(mmap32);
	return ret;
}
