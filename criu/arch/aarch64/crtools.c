#include <string.h>
#include <unistd.h>

#include <linux/elf.h>

#include "asm/types.h"
#include "asm/restorer.h"
#include "common/compiler.h"
#include "ptrace.h"
#include "asm/processor-flags.h"
#include "protobuf.h"
#include "images/core.pb-c.h"
#include "images/creds.pb-c.h"
#include "parasite-syscall.h"
#include "log.h"
#include "util.h"
#include "cpu.h"
#include "restorer.h"


/*
 * Injected syscall instruction
 */
const char code_syscall[] = {
	0x01, 0x00, 0x00, 0xd4,		/* SVC #0 */
	0x00, 0x00, 0x20, 0xd4		/* BRK #0 */
};

static const int
code_syscall_aligned = round_up(sizeof(code_syscall), sizeof(long));

static inline void __always_unused __check_code_syscall(void)
{
	BUILD_BUG_ON(code_syscall_aligned != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs)
{
	regs->pc = new_ip;
	if (stack)
		regs->sp = (unsigned long)stack;
}

bool arch_can_dump_task(struct parasite_ctl *ctl)
{
	/*
	 * TODO: Add proper check here
	 */
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
	user_regs_struct_t regs = ctl->orig.regs;
	int err;

	regs.regs[8] = (unsigned long)nr;
	regs.regs[0] = arg1;
	regs.regs[1] = arg2;
	regs.regs[2] = arg3;
	regs.regs[3] = arg4;
	regs.regs[4] = arg5;
	regs.regs[5] = arg6;
	regs.regs[6] = 0;
	regs.regs[7] = 0;

	err = __parasite_execute_syscall(ctl, &regs, code_syscall);

	*ret = regs.regs[0];
	return err;
}


#define assign_reg(dst, src, e)		dst->e = (__typeof__(dst->e))(src).e

int get_task_regs(pid_t pid, user_regs_struct_t regs, CoreEntry *core)
{
	struct iovec iov;
	user_fpregs_struct_t fpsimd;
	int i, ret;

	pr_info("Dumping GP/FPU registers for %d\n", pid);

	iov.iov_base = &regs;
	iov.iov_len = sizeof(user_regs_struct_t);
	if ((ret = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov))) {
		pr_perror("Failed to obtain CPU registers for %d", pid);
		goto err;
	}

	iov.iov_base = &fpsimd;
	iov.iov_len = sizeof(fpsimd);
	if ((ret = ptrace(PTRACE_GETREGSET, pid, NT_PRFPREG, &iov))) {
		pr_perror("Failed to obtain FPU registers for %d", pid);
		goto err;
	}


	// Save the Aarch64 CPU state
	for (i = 0; i < 31; ++i)
		assign_reg(core->ti_aarch64->gpregs, regs, regs[i]);
	assign_reg(core->ti_aarch64->gpregs, regs, sp);
	assign_reg(core->ti_aarch64->gpregs, regs, pc);
	assign_reg(core->ti_aarch64->gpregs, regs, pstate);


	// Save the FP/SIMD state
	for (i = 0; i < 32; ++i)
	{
		core->ti_aarch64->fpsimd->vregs[2*i]     = fpsimd.vregs[i];
		core->ti_aarch64->fpsimd->vregs[2*i + 1] = fpsimd.vregs[i] >> 64;
	}
	assign_reg(core->ti_aarch64->fpsimd, fpsimd, fpsr);
	assign_reg(core->ti_aarch64->fpsimd, fpsimd, fpcr);

	ret = 0;

err:
	return ret;
}

int arch_alloc_thread_info(CoreEntry *core)
{
	ThreadInfoAarch64 *ti_aarch64;
	UserAarch64RegsEntry *gpregs;
	UserAarch64FpsimdContextEntry *fpsimd;

	ti_aarch64 = xmalloc(sizeof(*ti_aarch64));
	if (!ti_aarch64)
		goto err;
	thread_info_aarch64__init(ti_aarch64);
	core->ti_aarch64 = ti_aarch64;

	gpregs = xmalloc(sizeof(*gpregs));
	if (!gpregs)
		goto err;
	user_aarch64_regs_entry__init(gpregs);

	gpregs->regs = xmalloc(31*sizeof(uint64_t));
	if (!gpregs->regs)
		goto err;
	gpregs->n_regs = 31;

	ti_aarch64->gpregs = gpregs;

	fpsimd = xmalloc(sizeof(*fpsimd));
	if (!fpsimd)
		goto err;
	user_aarch64_fpsimd_context_entry__init(fpsimd);
	ti_aarch64->fpsimd = fpsimd;
	fpsimd->vregs = xmalloc(64*sizeof(fpsimd->vregs[0]));
	fpsimd->n_vregs = 64;
	if (!fpsimd->vregs)
		goto err;

	return 0;
err:
	return -1;
}

void arch_free_thread_info(CoreEntry *core)
{
	if (CORE_THREAD_ARCH_INFO(core)) {
		if (CORE_THREAD_ARCH_INFO(core)->fpsimd) {
			xfree(CORE_THREAD_ARCH_INFO(core)->fpsimd->vregs);
			xfree(CORE_THREAD_ARCH_INFO(core)->fpsimd);
		}
		xfree(CORE_THREAD_ARCH_INFO(core)->gpregs->regs);
		xfree(CORE_THREAD_ARCH_INFO(core)->gpregs);
		xfree(CORE_THREAD_ARCH_INFO(core));
		CORE_THREAD_ARCH_INFO(core) = NULL;
	}
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core)
{
	int i;
	struct fpsimd_context *fpsimd = RT_SIGFRAME_FPU(sigframe);

	if (core->ti_aarch64->fpsimd->n_vregs != 64)
		return 1;

	for (i = 0; i < 32; ++i)
		fpsimd->vregs[i] =	(__uint128_t)core->ti_aarch64->fpsimd->vregs[2*i] |
					((__uint128_t)core->ti_aarch64->fpsimd->vregs[2*i + 1] << 64);
	assign_reg(fpsimd, *core->ti_aarch64->fpsimd, fpsr);
	assign_reg(fpsimd, *core->ti_aarch64->fpsimd, fpcr);

	fpsimd->head.magic = FPSIMD_MAGIC;
	fpsimd->head.size = sizeof(*fpsimd);

	return 0;
}

void *mmap_seized(
		struct parasite_ctl *ctl,
		void *addr, size_t length, int prot,
		int flags, int fd, off_t offset)
{
	unsigned long map;
	int err;

	err = syscall_seized(ctl, __NR_mmap, &map,
			(unsigned long)addr, length, prot, flags, fd, offset);
	if (err < 0 || (long)map < 0)
		map = 0;

	return (void *)map;
}

int restore_gpregs(struct rt_sigframe *f, UserRegsEntry *r)
{
#define CPREG1(d)       f->uc.uc_mcontext.d = r->d

	int i;

	for (i = 0; i < 31; ++i)
		CPREG1(regs[i]);
	CPREG1(sp);
	CPREG1(pc);
	CPREG1(pstate);

#undef CPREG1

	return 0;
}
