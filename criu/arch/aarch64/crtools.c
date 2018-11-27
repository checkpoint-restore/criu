#include <string.h>
#include <unistd.h>

#include <linux/elf.h>

#include "types.h"
#include <compel/asm/processor-flags.h>

#include <compel/asm/infect-types.h>
#include "asm/restorer.h"
#include "common/compiler.h"
#include <compel/ptrace.h>
#include "asm/dump.h"
#include "protobuf.h"
#include "images/core.pb-c.h"
#include "images/creds.pb-c.h"
#include "parasite-syscall.h"
#include "log.h"
#include "util.h"
#include "cpu.h"
#include "restorer.h"
#include <compel/compel.h>

#define assign_reg(dst, src, e)		dst->e = (__typeof__(dst->e))(src)->e

int save_task_regs(void *x, user_regs_struct_t *regs, user_fpregs_struct_t *fpsimd)
{
	int i;
	CoreEntry *core = x;

	// Save the Aarch64 CPU state
	for (i = 0; i < 31; ++i)
		assign_reg(core->ti_aarch64->gpregs, regs, regs[i]);
	assign_reg(core->ti_aarch64->gpregs, regs, sp);
	assign_reg(core->ti_aarch64->gpregs, regs, pc);
	assign_reg(core->ti_aarch64->gpregs, regs, pstate);


	// Save the FP/SIMD state
	for (i = 0; i < 32; ++i)
	{
		core->ti_aarch64->fpsimd->vregs[2*i]     = fpsimd->vregs[i];
		core->ti_aarch64->fpsimd->vregs[2*i + 1] = fpsimd->vregs[i] >> 64;
	}
	assign_reg(core->ti_aarch64->fpsimd, fpsimd, fpsr);
	assign_reg(core->ti_aarch64->fpsimd, fpsimd, fpcr);

	return 0;
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
	assign_reg(fpsimd, core->ti_aarch64->fpsimd, fpsr);
	assign_reg(fpsimd, core->ti_aarch64->fpsimd, fpcr);

	fpsimd->head.magic = FPSIMD_MAGIC;
	fpsimd->head.size = sizeof(*fpsimd);

	return 0;
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
