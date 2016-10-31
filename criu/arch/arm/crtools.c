#include <string.h>
#include <unistd.h>

#include "types.h"
#include <compel/asm/processor-flags.h>

#include <compel/asm/infect-types.h>
#include "asm/restorer.h"
#include "common/compiler.h"
#include "asm/dump.h"
#include <compel/ptrace.h>
#include "protobuf.h"
#include "images/core.pb-c.h"
#include "images/creds.pb-c.h"
#include "log.h"
#include "util.h"
#include "cpu.h"
#include "elf.h"
#include "parasite-syscall.h"
#include "restorer.h"

#include <compel/compel.h>

#define assign_reg(dst, src, e)		dst->e = (__typeof__(dst->e))((src)->ARM_##e)

int save_task_regs(void *x, user_regs_struct_t *regs, user_fpregs_struct_t *fpregs)
{
	CoreEntry *core = x;

	// Save the ARM CPU state

	assign_reg(core->ti_arm->gpregs, regs, r0);
	assign_reg(core->ti_arm->gpregs, regs, r1);
	assign_reg(core->ti_arm->gpregs, regs, r2);
	assign_reg(core->ti_arm->gpregs, regs, r3);
	assign_reg(core->ti_arm->gpregs, regs, r4);
	assign_reg(core->ti_arm->gpregs, regs, r5);
	assign_reg(core->ti_arm->gpregs, regs, r6);
	assign_reg(core->ti_arm->gpregs, regs, r7);
	assign_reg(core->ti_arm->gpregs, regs, r8);
	assign_reg(core->ti_arm->gpregs, regs, r9);
	assign_reg(core->ti_arm->gpregs, regs, r10);
	assign_reg(core->ti_arm->gpregs, regs, fp);
	assign_reg(core->ti_arm->gpregs, regs, ip);
	assign_reg(core->ti_arm->gpregs, regs, sp);
	assign_reg(core->ti_arm->gpregs, regs, lr);
	assign_reg(core->ti_arm->gpregs, regs, pc);
	assign_reg(core->ti_arm->gpregs, regs, cpsr);
	core->ti_arm->gpregs->orig_r0 = regs->ARM_ORIG_r0;


	// Save the VFP state

	memcpy(CORE_THREAD_ARCH_INFO(core)->fpstate->vfp_regs, &fpregs->fpregs, sizeof(fpregs->fpregs));
	CORE_THREAD_ARCH_INFO(core)->fpstate->fpscr = fpregs->fpscr;

	return 0;
}

int arch_alloc_thread_info(CoreEntry *core)
{
	ThreadInfoArm *ti_arm;
	UserArmRegsEntry *gpregs;
	UserArmVfpstateEntry *fpstate;

	ti_arm = xmalloc(sizeof(*ti_arm));
	if (!ti_arm)
		goto err;
	thread_info_arm__init(ti_arm);
	core->ti_arm = ti_arm;

	gpregs = xmalloc(sizeof(*gpregs));
	user_arm_regs_entry__init(gpregs);
	ti_arm->gpregs = gpregs;

	fpstate = xmalloc(sizeof(*fpstate));
	if (!fpstate)
		goto err;
	user_arm_vfpstate_entry__init(fpstate);
	ti_arm->fpstate = fpstate;
	fpstate->vfp_regs = xmalloc(32*sizeof(unsigned long long));
	fpstate->n_vfp_regs = 32;
	if (!fpstate->vfp_regs)
		goto err;

	return 0;
err:
	return -1;
}

void arch_free_thread_info(CoreEntry *core)
{
	if (CORE_THREAD_ARCH_INFO(core)) {
		if (CORE_THREAD_ARCH_INFO(core)->fpstate) {
			xfree(CORE_THREAD_ARCH_INFO(core)->fpstate->vfp_regs);
			xfree(CORE_THREAD_ARCH_INFO(core)->fpstate);
		}
		xfree(CORE_THREAD_ARCH_INFO(core)->gpregs);
		xfree(CORE_THREAD_ARCH_INFO(core));
		CORE_THREAD_ARCH_INFO(core) = NULL;
	}
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core)
{
	struct aux_sigframe *aux = (struct aux_sigframe *)&sigframe->sig.uc.uc_regspace;

	memcpy(&aux->vfp.ufp.fpregs, CORE_THREAD_ARCH_INFO(core)->fpstate->vfp_regs, sizeof(aux->vfp.ufp.fpregs));
	aux->vfp.ufp.fpscr = CORE_THREAD_ARCH_INFO(core)->fpstate->fpscr;
	aux->vfp.magic = VFP_MAGIC;
	aux->vfp.size = VFP_STORAGE_SIZE;
	return 0;
}

int restore_gpregs(struct rt_sigframe *f, UserArmRegsEntry *r)
{
#define CPREG1(d)       f->sig.uc.uc_mcontext.arm_##d = r->d
#define CPREG2(d, s)    f->sig.uc.uc_mcontext.arm_##d = r->s

	CPREG1(r0);
	CPREG1(r1);
	CPREG1(r2);
	CPREG1(r3);
	CPREG1(r4);
	CPREG1(r5);
	CPREG1(r6);
	CPREG1(r7);
	CPREG1(r8);
	CPREG1(r9);
	CPREG1(r10);
	CPREG1(fp);
	CPREG1(ip);
	CPREG1(sp);
	CPREG1(lr);
	CPREG1(pc);
	CPREG1(cpsr);

#undef CPREG1
#undef CPREG2

	return 0;
}
