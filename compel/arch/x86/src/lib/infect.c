#include <sys/types.h>
#include <sys/uio.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#include <compel/asm/fpu.h>

#include "asm/cpu.h"

#include <compel/asm/processor-flags.h>
#include <compel/cpu.h>
#include "errno.h"
#include <compel/plugins/std/syscall-codes.h>
#include <compel/plugins/std/syscall.h>
#include "common/err.h"
#include "asm/infect-types.h"
#include "ptrace.h"
#include "infect.h"
#include "infect-priv.h"
#include "log.h"

#ifndef NT_X86_XSTATE
#define NT_X86_XSTATE 0x202 /* x86 extended state using xsave */
#endif

#ifndef NT_X86_SHSTK
#define NT_X86_SHSTK 0x204	/* x86 shstk state */
#endif

#ifndef ARCH_SHSTK_STATUS
#define ARCH_SHSTK_STATUS	0x5005
#define ARCH_SHSTK_SHSTK	(1ULL << 0)
#endif

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1 /* Contains copy of prstatus struct */
#endif

/*
 * Injected syscall instruction
 */
const char code_syscall[] = {
	0x0f, 0x05,			   /* syscall    */
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc /* int 3, ... */
};

const char code_int_80[] = {
	0xcd, 0x80,			   /* int $0x80  */
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc /* int 3, ... */
};

static const int code_syscall_aligned = round_up(sizeof(code_syscall), sizeof(long));
static const int code_int_80_aligned = round_up(sizeof(code_syscall), sizeof(long));

static inline __always_unused void __check_code_syscall(void)
{
	BUILD_BUG_ON(code_int_80_aligned != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(code_syscall_aligned != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

/* 10-byte legacy floating point register */
struct fpreg {
	uint16_t significand[4];
	uint16_t exponent;
};

/* 16-byte floating point register */
struct fpxreg {
	uint16_t significand[4];
	uint16_t exponent;
	uint16_t padding[3];
};

#define FPREG_ADDR(f, n)   ((void *)&(f)->st_space + (n)*16)
#define FP_EXP_TAG_VALID   0
#define FP_EXP_TAG_ZERO	   1
#define FP_EXP_TAG_SPECIAL 2
#define FP_EXP_TAG_EMPTY   3

static inline uint32_t twd_fxsr_to_i387(struct i387_fxsave_struct *fxsave)
{
	struct fpxreg *st;
	uint32_t tos = (fxsave->swd >> 11) & 7;
	uint32_t twd = (unsigned long)fxsave->twd;
	uint32_t tag;
	uint32_t ret = 0xffff0000u;
	int i;

	for (i = 0; i < 8; i++, twd >>= 1) {
		if (twd & 0x1) {
			st = FPREG_ADDR(fxsave, (i - tos) & 7);

			switch (st->exponent & 0x7fff) {
			case 0x7fff:
				tag = FP_EXP_TAG_SPECIAL;
				break;
			case 0x0000:
				if (!st->significand[0] && !st->significand[1] && !st->significand[2] &&
				    !st->significand[3])
					tag = FP_EXP_TAG_ZERO;
				else
					tag = FP_EXP_TAG_SPECIAL;
				break;
			default:
				if (st->significand[3] & 0x8000)
					tag = FP_EXP_TAG_VALID;
				else
					tag = FP_EXP_TAG_SPECIAL;
				break;
			}
		} else {
			tag = FP_EXP_TAG_EMPTY;
		}
		ret |= tag << (2 * i);
	}
	return ret;
}

void compel_convert_from_fxsr(struct user_i387_ia32_struct *env, struct i387_fxsave_struct *fxsave)
{
	struct fpxreg *from = (struct fpxreg *)&fxsave->st_space[0];
	struct fpreg *to = (struct fpreg *)env->st_space;
	int i;

	env->cwd = fxsave->cwd | 0xffff0000u;
	env->swd = fxsave->swd | 0xffff0000u;
	env->twd = twd_fxsr_to_i387(fxsave);

	env->fip = fxsave->rip;
	env->foo = fxsave->rdp;
	/*
	 * should be actually ds/cs at fpu exception time, but
	 * that information is not available in 64bit mode.
	 */
	env->fcs = 0x23; /* __USER32_CS */
	env->fos = 0x2b; /* __USER32_DS */
	env->fos |= 0xffff0000;

	for (i = 0; i < 8; ++i)
		memcpy(&to[i], &from[i], sizeof(to[0]));
}

int sigreturn_prep_regs_plain(struct rt_sigframe *sigframe, user_regs_struct_t *regs, user_fpregs_struct_t *fpregs)
{
	bool is_native = user_regs_native(regs);
	fpu_state_t *fpu_state = is_native ? &sigframe->native.fpu_state : &sigframe->compat.fpu_state;
	if (is_native) {
#define cpreg64_native(d, s) sigframe->native.uc.uc_mcontext.d = regs->native.s
		cpreg64_native(rdi, di);
		cpreg64_native(rsi, si);
		cpreg64_native(rbp, bp);
		cpreg64_native(rsp, sp);
		cpreg64_native(rbx, bx);
		cpreg64_native(rdx, dx);
		cpreg64_native(rcx, cx);
		cpreg64_native(rip, ip);
		cpreg64_native(rax, ax);
		cpreg64_native(r8, r8);
		cpreg64_native(r9, r9);
		cpreg64_native(r10, r10);
		cpreg64_native(r11, r11);
		cpreg64_native(r12, r12);
		cpreg64_native(r13, r13);
		cpreg64_native(r14, r14);
		cpreg64_native(r15, r15);
		cpreg64_native(cs, cs);
		cpreg64_native(eflags, flags);

		sigframe->is_native = true;
#undef cpreg64_native
	} else {
#define cpreg32_compat(d) sigframe->compat.uc.uc_mcontext.d = regs->compat.d
		cpreg32_compat(gs);
		cpreg32_compat(fs);
		cpreg32_compat(es);
		cpreg32_compat(ds);
		cpreg32_compat(di);
		cpreg32_compat(si);
		cpreg32_compat(bp);
		cpreg32_compat(sp);
		cpreg32_compat(bx);
		cpreg32_compat(dx);
		cpreg32_compat(cx);
		cpreg32_compat(ip);
		cpreg32_compat(ax);
		cpreg32_compat(cs);
		cpreg32_compat(ss);
		cpreg32_compat(flags);
#undef cpreg32_compat
		sigframe->is_native = false;
	}

	fpu_state->has_fpu = true;
	if (is_native) {
		memcpy(&fpu_state->fpu_state_64.xsave, fpregs, sizeof(*fpregs));
	} else {
		memcpy(&fpu_state->fpu_state_ia32.xsave, fpregs, sizeof(*fpregs));
		compel_convert_from_fxsr(&fpu_state->fpu_state_ia32.fregs_state.i387_ia32,
					 &fpu_state->fpu_state_ia32.xsave.i387);
	}

	return 0;
}

int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe)
{
	fpu_state_t *fpu_state = (sigframe->is_native) ? &rsigframe->native.fpu_state : &rsigframe->compat.fpu_state;

	if (sigframe->is_native) {
		unsigned long addr = (unsigned long)(void *)&fpu_state->fpu_state_64.xsave;

		if ((addr % 64ul)) {
			pr_err("Unaligned address passed: %lx (native %d)\n", addr, sigframe->is_native);
			return -1;
		}

		sigframe->native.uc.uc_mcontext.fpstate = (uint64_t)addr;
	} else if (!sigframe->is_native) {
		sigframe->compat.uc.uc_mcontext.fpstate = (uint32_t)(unsigned long)(void *)&fpu_state->fpu_state_ia32;
	}

	return 0;
}

#define get_signed_user_reg(pregs, name) \
	((user_regs_native(pregs)) ? (int64_t)((pregs)->native.name) : (int32_t)((pregs)->compat.name))

static int get_task_fpregs(pid_t pid, user_fpregs_struct_t *xsave)
{
	if (ptrace(PTRACE_GETFPREGS, pid, NULL, xsave)) {
		pr_perror("Can't obtain FPU registers for %d", pid);
		return -1;
	}

	return 0;
}

static int get_task_xsave(pid_t pid, user_fpregs_struct_t *xsave)
{
	struct iovec iov;

	iov.iov_base = xsave;
	iov.iov_len = sizeof(*xsave);

	if (ptrace(PTRACE_GETREGSET, pid, (unsigned int)NT_X86_XSTATE, &iov) < 0) {
		pr_perror("Can't obtain FPU registers for %d", pid);
		return -1;
	}

	if ((xsave->xsave_hdr.xstate_bv & 3) != 3) {
		// Due to init-optimisation [1] x87 FPU or SSE state may not be filled in.
		// Since those are restored unconditionally, make sure the init values are
		// filled by retrying with old PTRACE_GETFPREGS.
		//
		// [1] Intel® 64 and IA-32 Architectures Software Developer's
		//     Manual Volume 1: Basic Architecture
		//     Section 13.6: Processor tracking of XSAVE-managed state
		if (get_task_fpregs(pid, xsave))
			return -1;
	}

	/*
	 * xsave may be on stack, if we don't clear it explicitly we get
	 * funky shadow stack state
	 */
	memset(&xsave->cet, 0, sizeof(xsave->cet));
	if (compel_cpu_has_feature(X86_FEATURE_SHSTK)) {
		unsigned long ssp = 0;
		unsigned long features = 0;

		if (ptrace(PTRACE_ARCH_PRCTL, pid, (unsigned long)&features, ARCH_SHSTK_STATUS)) {
			/*
			 * kernels that don't support shadow stack return
			 * -EINVAL
			 */
			if (errno == EINVAL)
				return 0;

			pr_perror("shstk: can't get shadow stack status for %d", pid);
			return -1;
		}

		if (!(features & ARCH_SHSTK_SHSTK))
			return 0;

		iov.iov_base = &ssp;
		iov.iov_len = sizeof(ssp);

		if (ptrace(PTRACE_GETREGSET, pid, (unsigned int)NT_X86_SHSTK, &iov) < 0) {
			/* ENODEV means CET is not supported by the CPU  */
			if (errno != ENODEV) {
				pr_perror("shstk: can't get SSP for %d", pid);
				return -1;
			}
		}

		xsave->cet.cet = features;
		xsave->cet.ssp = ssp;

		pr_debug("%d: shstk: cet: %lx ssp: %lx\n", pid, xsave->cet.cet, xsave->cet.ssp);
	}

	return 0;
}

static inline void fixup_mxcsr(struct xsave_struct *xsave)
{
	/*
	 * Right now xsave->i387.mxcsr filled with the random garbage,
	 * let's make it valid by applying mask which allows all
	 * features, except the denormals-are-zero feature bit.
	 *
	 * See also fpu__init_system_mxcsr function:
	 * https://github.com/torvalds/linux/blob/8cb1ae19/arch/x86/kernel/fpu/init.c#L117
	 */
	xsave->i387.mxcsr &= 0x0000ffbf;
}

/* See arch/x86/kernel/fpu/xstate.c */
static void validate_random_xstate(struct xsave_struct *xsave)
{
	struct xsave_hdr_struct *hdr = &xsave->xsave_hdr;
	unsigned int i;

	/* No unknown or supervisor features may be set */
	hdr->xstate_bv &= XFEATURE_MASK_USER;
	hdr->xstate_bv &= ~XFEATURE_MASK_SUPERVISOR;
	hdr->xstate_bv &= XFEATURE_MASK_FAULTINJ;

	for (i = 0; i < XFEATURE_MAX; i++) {
		if (!compel_fpu_has_feature(i))
			hdr->xstate_bv &= ~(1 << i);
	}

	/* Userspace must use the uncompacted format */
	hdr->xcomp_bv = 0;

	/*
	 * If 'reserved' is shrunken to add a new field, make sure to validate
	 * that new field here!
	 */
	BUILD_BUG_ON(sizeof(hdr->reserved) != 48);

	/* No reserved bits may be set */
	memset(&hdr->reserved, 0, sizeof(hdr->reserved));
}

/*
 * TODO: Put fault-injection under CONFIG_* and move
 * extended regset corruption to generic code
 */
static int corrupt_extregs(pid_t pid)
{
	bool use_xsave = compel_cpu_has_feature(X86_FEATURE_OSXSAVE);
	user_fpregs_struct_t ext_regs;
	int *rand_to = (int *)&ext_regs;
	unsigned int seed, init_seed;
	size_t i;

	init_seed = seed = time(NULL);
	for (i = 0; i < sizeof(ext_regs) / sizeof(int); i++)
		*rand_to++ = rand_r(&seed);

	/*
	 * Error log-level as:
	 *  - not intended to be used outside of testing;
	 *  - zdtm.py will grep it auto-magically from logs
	 *    (and the seed will be known from automatic testing).
	 */
	pr_err("Corrupting %s for %d, seed %u\n", use_xsave ? "xsave" : "fpuregs", pid, init_seed);

	fixup_mxcsr(&ext_regs);

	if (!use_xsave) {
		if (ptrace(PTRACE_SETFPREGS, pid, NULL, &ext_regs)) {
			pr_perror("Can't set FPU registers for %d", pid);
			return -1;
		}
	} else {
		struct iovec iov;

		validate_random_xstate((void *)&ext_regs);

		iov.iov_base = &ext_regs;
		iov.iov_len = sizeof(ext_regs);

		if (ptrace(PTRACE_SETREGSET, pid, (unsigned int)NT_X86_XSTATE, &iov) < 0) {
			pr_perror("Can't set xstate for %d", pid);
			return -1;
		}
	}
	return 0;
}

int compel_get_task_regs(pid_t pid, user_regs_struct_t *regs, user_fpregs_struct_t *xs, save_regs_t save,
			 void *arg, unsigned long flags)
{
	int ret = -1;

	pr_info("Dumping general registers for %d in %s mode\n", pid, user_regs_native(regs) ? "native" : "compat");

	/* Did we come from a system call? */
	if (get_signed_user_reg(regs, orig_ax) >= 0) {
		/* Restart the system call */
		switch (get_signed_user_reg(regs, ax)) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			set_user_reg(regs, ax, get_user_reg(regs, orig_ax));
			set_user_reg(regs, ip, get_user_reg(regs, ip) - 2);
			break;
		case -ERESTART_RESTARTBLOCK:
			pr_warn("Will restore %d with interrupted system call\n", pid);
			set_user_reg(regs, ax, -EINTR);
			break;
		}
	}

	if (!compel_cpu_has_feature(X86_FEATURE_FPU))
		goto out;

	/*
	 * FPU fetched either via fxsave or via xsave,
	 * thus decode it accordingly.
	 */

	pr_info("Dumping GP/FPU registers for %d\n", pid);

	if (!compel_cpu_has_feature(X86_FEATURE_OSXSAVE)) {
		ret = get_task_fpregs(pid, xs);
	} else if (unlikely(flags & INFECT_X86_PTRACE_MXCSR_BUG)) {
		/*
		 * get_task_fpregs() will fill FP state,
		 * get_task_xsave() will overwrite rightly sse/mmx/etc
		 */
		pr_warn("Skylake xsave fpu bug workaround used\n");
		ret = get_task_fpregs(pid, xs);
		if (!ret)
			ret = get_task_xsave(pid, xs);
	} else {
		ret = get_task_xsave(pid, xs);
	}

	if (!ret && unlikely(flags & INFECT_CORRUPT_EXTREGS))
		ret = corrupt_extregs(pid);

	if (ret)
		goto err;

out:
	ret = save(pid, arg, regs, xs);
err:
	return ret;
}

int compel_set_task_ext_regs(pid_t pid, user_fpregs_struct_t *ext_regs)
{
	struct iovec iov;

	pr_info("Restoring GP/FPU registers for %d\n", pid);

	if (!compel_cpu_has_feature(X86_FEATURE_OSXSAVE)) {
		if (ptrace(PTRACE_SETFPREGS, pid, NULL, ext_regs)) {
			pr_perror("Can't set FPU registers for %d", pid);
			return -1;
		}
		return 0;
	}

	iov.iov_base = ext_regs;
	iov.iov_len = sizeof(*ext_regs);

	if (ptrace(PTRACE_SETREGSET, pid, (unsigned int)NT_X86_XSTATE, &iov) < 0) {
		pr_perror("Can't set FPU registers for %d", pid);
		return -1;
	}

	return 0;
}

int compel_syscall(struct parasite_ctl *ctl, int nr, long *ret, unsigned long arg1, unsigned long arg2,
		   unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	user_regs_struct_t regs = ctl->orig.regs;
	bool native = user_regs_native(&regs);
	int err;

	if (native) {
		user_regs_struct64 *r = &regs.native;

		r->ax = (uint64_t)nr;
		r->di = arg1;
		r->si = arg2;
		r->dx = arg3;
		r->r10 = arg4;
		r->r8 = arg5;
		r->r9 = arg6;

		err = compel_execute_syscall(ctl, &regs, code_syscall);
	} else {
		user_regs_struct32 *r = &regs.compat;

		r->ax = (uint32_t)nr;
		r->bx = arg1;
		r->cx = arg2;
		r->dx = arg3;
		r->si = arg4;
		r->di = arg5;
		r->bp = arg6;

		err = compel_execute_syscall(ctl, &regs, code_int_80);
	}

	*ret = native ? (long)get_user_reg(&regs, ax) : (int)get_user_reg(&regs, ax);
	return err;
}

void *remote_mmap(struct parasite_ctl *ctl, void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	long map;
	int err;
	bool compat_task = !user_regs_native(&ctl->orig.regs);

	err = compel_syscall(ctl, __NR(mmap, compat_task), &map, (unsigned long)addr, length, prot, flags, fd, offset);
	if (err < 0)
		return NULL;

	if (map == -EACCES && (prot & PROT_WRITE) && (prot & PROT_EXEC)) {
		pr_warn("mmap(PROT_WRITE | PROT_EXEC) failed for %d, "
			"check selinux execmem policy\n",
			ctl->rpid);
		return NULL;
	}
	if (IS_ERR_VALUE(map)) {
		pr_err("remote mmap() failed: %s\n", strerror(-map));
		return NULL;
	}

	/*
	 * For compat tasks the address in foreign process
	 * must lay inside 4 bytes.
	 */
	if (compat_task)
		map &= 0xfffffffful;

	return (void *)map;
}

/*
 * regs must be inited when calling this function from original context
 */
void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs)
{
	set_user_reg(regs, ip, new_ip);
	if (stack)
		set_user_reg(regs, sp, (unsigned long)stack);

	/* Avoid end of syscall processing */
	set_user_reg(regs, orig_ax, -1);

	/* Make sure flags are in known state */
	set_user_reg(regs, flags, get_user_reg(regs, flags) & ~(X86_EFLAGS_TF | X86_EFLAGS_DF | X86_EFLAGS_IF));
}

#define USER32_CS 0x23
#define USER_CS	  0x33

static bool ldt_task_selectors(pid_t pid)
{
	unsigned long cs;

	errno = 0;
	/*
	 * Offset of register must be from 64-bit set even for
	 * compatible tasks. Fix this to support native i386 tasks
	 */
	cs = ptrace(PTRACE_PEEKUSER, pid, offsetof(user_regs_struct64, cs), 0);
	if (errno != 0) {
		pr_perror("Can't get CS register for %d", pid);
		return -1;
	}

	return cs != USER_CS && cs != USER32_CS;
}

static int arch_task_compatible(pid_t pid)
{
	user_regs_struct_t r;
	int ret = ptrace_get_regs(pid, &r);

	if (ret)
		return -1;

	return !user_regs_native(&r);
}

bool arch_can_dump_task(struct parasite_ctl *ctl)
{
	pid_t pid = ctl->rpid;
	int ret;

	ret = arch_task_compatible(pid);
	if (ret < 0)
		return false;

	if (ret && !(ctl->ictx.flags & INFECT_COMPATIBLE)) {
		pr_err("Can't dump task %d running in 32-bit mode\n", pid);
		return false;
	}

	if (ldt_task_selectors(pid)) {
		pr_err("Can't dump task %d with LDT descriptors\n", pid);
		return false;
	}

	return true;
}

int arch_fetch_sas(struct parasite_ctl *ctl, struct rt_sigframe *s)
{
	int native = compel_mode_native(ctl);
	void *where = native ? (void *)&s->native.uc.uc_stack : (void *)&s->compat.uc.uc_stack;
	long ret;
	int err;

	err = compel_syscall(ctl, __NR(sigaltstack, !native), &ret, 0, (unsigned long)where, 0, 0, 0, 0);
	return err ? err : ret;
}

/* Copied from the gdb header gdb/nat/x86-dregs.h */

/* Debug registers' indices.  */
#define DR_FIRSTADDR 0
#define DR_LASTADDR  3
#define DR_NADDR     4 /* The number of debug address registers.  */
#define DR_STATUS    6 /* Index of debug status register (DR6).  */
#define DR_CONTROL   7 /* Index of debug control register (DR7).  */

#define DR_LOCAL_ENABLE_SHIFT  0 /* Extra shift to the local enable bit.  */
#define DR_GLOBAL_ENABLE_SHIFT 1 /* Extra shift to the global enable bit.  */
#define DR_ENABLE_SIZE	       2 /* Two enable bits per debug register.  */

/* Locally enable the break/watchpoint in the I'th debug register.  */
#define X86_DR_LOCAL_ENABLE(i) (1 << (DR_LOCAL_ENABLE_SHIFT + DR_ENABLE_SIZE * (i)))

int ptrace_set_breakpoint(pid_t pid, void *addr)
{
	k_rtsigset_t block;
	int ret;

	/* Set a breakpoint */
	if (ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[DR_FIRSTADDR]), addr)) {
		pr_perror("Unable to setup a breakpoint into %d", pid);
		return -1;
	}

	/* Enable the breakpoint */
	if (ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[DR_CONTROL]),
		   X86_DR_LOCAL_ENABLE(DR_FIRSTADDR))) {
		pr_perror("Unable to enable the breakpoint for %d", pid);
		return -1;
	}

	/*
	 * FIXME(issues/1429): SIGTRAP can't be blocked, otherwise its handler
	 * will be reset to the default one.
	 */
	ksigfillset(&block);
	ksigdelset(&block, SIGTRAP);
	if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(k_rtsigset_t), &block)) {
		pr_perror("Can't block signals for %d", pid);
		return -1;
	}
	ret = ptrace(PTRACE_CONT, pid, NULL, NULL);
	if (ret) {
		pr_perror("Unable to restart the  stopped tracee process %d", pid);
		return -1;
	}

	return 1;
}

int ptrace_flush_breakpoints(pid_t pid)
{
	/* Disable the breakpoint */
	if (ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[DR_CONTROL]), 0)) {
		pr_perror("Unable to disable the breakpoint for %d", pid);
		return -1;
	}

	return 0;
}

int ptrace_get_regs(pid_t pid, user_regs_struct_t *regs)
{
	struct iovec iov;
	int ret;

	iov.iov_base = &regs->native;
	iov.iov_len = sizeof(user_regs_struct64);

	ret = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
	if (ret == -1) {
		pr_perror("PTRACE_GETREGSET failed");
		return -1;
	}

	if (iov.iov_len == sizeof(regs->native)) {
		regs->__is_native = NATIVE_MAGIC;
		return ret;
	}
	if (iov.iov_len == sizeof(regs->compat)) {
		regs->__is_native = COMPAT_MAGIC;
		return ret;
	}

	pr_err("PTRACE_GETREGSET read %zu bytes for pid %d, but native/compat regs sizes are %zu/%zu bytes\n",
	       iov.iov_len, pid, sizeof(regs->native), sizeof(regs->compat));
	return -1;
}

int ptrace_set_regs(pid_t pid, user_regs_struct_t *regs)
{
	struct iovec iov;

	if (user_regs_native(regs)) {
		iov.iov_base = &regs->native;
		iov.iov_len = sizeof(user_regs_struct64);
	} else {
		iov.iov_base = &regs->compat;
		iov.iov_len = sizeof(user_regs_struct32);
	}
	return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

#define TASK_SIZE ((1UL << 47) - PAGE_SIZE)
/*
 * Task size may be limited to 3G but we need a
 * higher limit, because it's backward compatible.
 */
#define TASK_SIZE_IA32 (0xffffe000)

unsigned long compel_task_size(void)
{
	return TASK_SIZE;
}

bool __compel_shstk_enabled(user_fpregs_struct_t *ext_regs)
{
	if (!compel_cpu_has_feature(X86_FEATURE_SHSTK))
		return false;

	if (ext_regs->cet.cet & ARCH_SHSTK_SHSTK)
		return true;

	return false;
}

int parasite_setup_shstk(struct parasite_ctl *ctl, user_fpregs_struct_t *ext_regs)
{
	pid_t pid = ctl->rpid;
	unsigned long sa_restorer = ctl->parasite_ip;
	unsigned long long ssp;
	unsigned long token;
	struct iovec iov;

	if (!compel_shstk_enabled(ext_regs))
		return 0;

	iov.iov_base = &ssp;
	iov.iov_len = sizeof(ssp);
	if (ptrace(PTRACE_GETREGSET, pid, (unsigned int)NT_X86_SHSTK, &iov) < 0) {
		/* ENODEV means CET is not supported by the CPU  */
		if (errno != ENODEV) {
			pr_perror("shstk: %d: cannot get SSP", pid);
			return -1;
		}
	}

	/* The token is for 64-bit */
	token = ALIGN_DOWN(ssp, 8);
	token |= (1UL << 63);
	ssp = ALIGN_DOWN(ssp, 8) - 8;
	if (ptrace(PTRACE_POKEDATA, pid, (void *)ssp, token)) {
		pr_perror("shstk: %d: failed to inject shadow stack token", pid);
		return -1;
	}

	ssp = ssp - sizeof(uint64_t);
	if (ptrace(PTRACE_POKEDATA, pid, (void *)ssp, sa_restorer)) {
		pr_perror("shstk: %d: failed to inject restorer address", pid);
		return -1;
	}

	ssp = ssp + sizeof(uint64_t);
	if (ptrace(PTRACE_SETREGSET, pid, (unsigned int)NT_X86_SHSTK, &iov) < 0) {
		pr_perror("shstk: %d: cannot write SSP", pid);
		return -1;
	}

	return 0;
}
