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
#include "compel/infect.h"

#define assign_reg(dst, src, e) dst->e = (__typeof__(dst->e))(src)->e

int save_task_regs(pid_t pid, void *x, user_regs_struct_t *regs, user_fpregs_struct_t *fpsimd)
{
	int i;
	CoreEntry *core = x;

	// Save riscv64 gprs
	assign_reg(core->ti_riscv64->gpregs, regs, pc);
	assign_reg(core->ti_riscv64->gpregs, regs, ra);
	assign_reg(core->ti_riscv64->gpregs, regs, sp);
	assign_reg(core->ti_riscv64->gpregs, regs, gp);
	assign_reg(core->ti_riscv64->gpregs, regs, tp);
	assign_reg(core->ti_riscv64->gpregs, regs, t0);
	assign_reg(core->ti_riscv64->gpregs, regs, t1);
	assign_reg(core->ti_riscv64->gpregs, regs, t2);
	assign_reg(core->ti_riscv64->gpregs, regs, s0);
	assign_reg(core->ti_riscv64->gpregs, regs, s1);
	assign_reg(core->ti_riscv64->gpregs, regs, a0);
	assign_reg(core->ti_riscv64->gpregs, regs, a1);
	assign_reg(core->ti_riscv64->gpregs, regs, a2);
	assign_reg(core->ti_riscv64->gpregs, regs, a3);
	assign_reg(core->ti_riscv64->gpregs, regs, a4);
	assign_reg(core->ti_riscv64->gpregs, regs, a5);
	assign_reg(core->ti_riscv64->gpregs, regs, a6);
	assign_reg(core->ti_riscv64->gpregs, regs, a7);
	assign_reg(core->ti_riscv64->gpregs, regs, s2);
	assign_reg(core->ti_riscv64->gpregs, regs, s3);
	assign_reg(core->ti_riscv64->gpregs, regs, s4);
	assign_reg(core->ti_riscv64->gpregs, regs, s5);
	assign_reg(core->ti_riscv64->gpregs, regs, s6);
	assign_reg(core->ti_riscv64->gpregs, regs, s7);
	assign_reg(core->ti_riscv64->gpregs, regs, s8);
	assign_reg(core->ti_riscv64->gpregs, regs, s9);
	assign_reg(core->ti_riscv64->gpregs, regs, s10);
	assign_reg(core->ti_riscv64->gpregs, regs, s11);
	assign_reg(core->ti_riscv64->gpregs, regs, t3);
	assign_reg(core->ti_riscv64->gpregs, regs, t4);
	assign_reg(core->ti_riscv64->gpregs, regs, t5);
	assign_reg(core->ti_riscv64->gpregs, regs, t6);

	// Save riscv64 fprs
	for (i = 0; i < 32; ++i)
		assign_reg(core->ti_riscv64->fpsimd, fpsimd, f[i]);
	assign_reg(core->ti_riscv64->fpsimd, fpsimd, fcsr);

	return 0;
}

int arch_alloc_thread_info(CoreEntry *core)
{
	ThreadInfoRiscv64 *ti_riscv64;
	UserRiscv64RegsEntry *gpregs;
	UserRiscv64DExtEntry *fpsimd;

	ti_riscv64 = xmalloc(sizeof(*ti_riscv64));
	if (!ti_riscv64)
		goto err;
	thread_info_riscv64__init(ti_riscv64);
	core->ti_riscv64 = ti_riscv64;

	gpregs = xmalloc(sizeof(*gpregs));
	if (!gpregs)
		goto err;
	user_riscv64_regs_entry__init(gpregs);

	ti_riscv64->gpregs = gpregs;

	fpsimd = xmalloc(sizeof(*fpsimd));
	if (!fpsimd)
		goto err;
	user_riscv64_d_ext_entry__init(fpsimd);
	ti_riscv64->fpsimd = fpsimd;
	fpsimd->f = xmalloc(32 * sizeof(fpsimd->f[0]));
	fpsimd->n_f = 32;
	if (!fpsimd->f)
		goto err;

	return 0;
err:
	return -1;
}

void arch_free_thread_info(CoreEntry *core)
{
	if (core->ti_riscv64) {
		if (core->ti_riscv64->fpsimd) {
			xfree(core->ti_riscv64->fpsimd->f);
			xfree(core->ti_riscv64->fpsimd);
		}
		xfree(core->ti_riscv64->gpregs);
		xfree(core->ti_riscv64);
		core->ti_riscv64 = NULL;
	}
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core)
{
	int i;
	UserRiscv64DExtEntry *fpsimd = core->ti_riscv64->fpsimd;

	if (fpsimd->n_f != 32)
		return 1;

	for (i = 0; i < 32; ++i)
		sigframe->uc.uc_mcontext.__fpregs.__d.__f[i] = fpsimd->f[i];
	sigframe->uc.uc_mcontext.__fpregs.__d.__fcsr = fpsimd->fcsr;

	return 0;
}

int restore_gpregs(struct rt_sigframe *f, UserRiscv64RegsEntry *r)
{
	f->uc.uc_mcontext.__gregs[0] = r->pc;
	f->uc.uc_mcontext.__gregs[1] = r->ra;
	f->uc.uc_mcontext.__gregs[2] = r->sp;
	f->uc.uc_mcontext.__gregs[3] = r->gp;
	f->uc.uc_mcontext.__gregs[4] = r->tp;
	f->uc.uc_mcontext.__gregs[5] = r->t0;
	f->uc.uc_mcontext.__gregs[6] = r->t1;
	f->uc.uc_mcontext.__gregs[7] = r->t2;
	f->uc.uc_mcontext.__gregs[8] = r->s0;
	f->uc.uc_mcontext.__gregs[9] = r->s1;
	f->uc.uc_mcontext.__gregs[10] = r->a0;
	f->uc.uc_mcontext.__gregs[11] = r->a1;
	f->uc.uc_mcontext.__gregs[12] = r->a2;
	f->uc.uc_mcontext.__gregs[13] = r->a3;
	f->uc.uc_mcontext.__gregs[14] = r->a4;
	f->uc.uc_mcontext.__gregs[15] = r->a5;
	f->uc.uc_mcontext.__gregs[16] = r->a6;
	f->uc.uc_mcontext.__gregs[17] = r->a7;
	f->uc.uc_mcontext.__gregs[18] = r->s2;
	f->uc.uc_mcontext.__gregs[19] = r->s3;
	f->uc.uc_mcontext.__gregs[20] = r->s4;
	f->uc.uc_mcontext.__gregs[21] = r->s5;
	f->uc.uc_mcontext.__gregs[22] = r->s6;
	f->uc.uc_mcontext.__gregs[23] = r->s7;
	f->uc.uc_mcontext.__gregs[24] = r->s8;
	f->uc.uc_mcontext.__gregs[25] = r->s9;
	f->uc.uc_mcontext.__gregs[26] = r->s10;
	f->uc.uc_mcontext.__gregs[27] = r->s11;
	f->uc.uc_mcontext.__gregs[28] = r->t3;
	f->uc.uc_mcontext.__gregs[29] = r->t4;
	f->uc.uc_mcontext.__gregs[30] = r->t5;
	f->uc.uc_mcontext.__gregs[31] = r->t6;

	return 0;
}
