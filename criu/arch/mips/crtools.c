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

#include "protobuf.h"
#include "images/core.pb-c.h"
#include "images/creds.pb-c.h"

int save_task_regs(pid_t pid, void *x, user_regs_struct_t *regs, user_fpregs_struct_t *fpregs)
{
	CoreEntry *core = x;

	/* Save the MIPS CPU state */
	core->ti_mips->gpregs->r0 = regs->regs[0];
	core->ti_mips->gpregs->r1 = regs->regs[1];
	core->ti_mips->gpregs->r2 = regs->regs[2];
	core->ti_mips->gpregs->r3 = regs->regs[3];
	core->ti_mips->gpregs->r4 = regs->regs[4];
	core->ti_mips->gpregs->r5 = regs->regs[5];
	core->ti_mips->gpregs->r6 = regs->regs[6];
	core->ti_mips->gpregs->r7 = regs->regs[7];
	core->ti_mips->gpregs->r8 = regs->regs[8];
	core->ti_mips->gpregs->r9 = regs->regs[9];
	core->ti_mips->gpregs->r10 = regs->regs[10];
	core->ti_mips->gpregs->r11 = regs->regs[11];
	core->ti_mips->gpregs->r12 = regs->regs[12];
	core->ti_mips->gpregs->r13 = regs->regs[13];
	core->ti_mips->gpregs->r14 = regs->regs[14];
	core->ti_mips->gpregs->r15 = regs->regs[15];
	core->ti_mips->gpregs->r16 = regs->regs[16];
	core->ti_mips->gpregs->r17 = regs->regs[17];
	core->ti_mips->gpregs->r18 = regs->regs[18];
	core->ti_mips->gpregs->r19 = regs->regs[19];
	core->ti_mips->gpregs->r20 = regs->regs[20];
	core->ti_mips->gpregs->r21 = regs->regs[21];
	core->ti_mips->gpregs->r22 = regs->regs[22];
	core->ti_mips->gpregs->r23 = regs->regs[23];
	core->ti_mips->gpregs->r24 = regs->regs[24];
	core->ti_mips->gpregs->r25 = regs->regs[25];
	core->ti_mips->gpregs->r26 = regs->regs[26];
	core->ti_mips->gpregs->r27 = regs->regs[27];
	core->ti_mips->gpregs->r28 = regs->regs[28];
	core->ti_mips->gpregs->r29 = regs->regs[29];
	core->ti_mips->gpregs->r30 = regs->regs[30];
	core->ti_mips->gpregs->r31 = regs->regs[31];

	core->ti_mips->gpregs->lo = regs->lo;
	core->ti_mips->gpregs->hi = regs->hi;
	core->ti_mips->gpregs->cp0_epc = regs->cp0_epc;
	core->ti_mips->gpregs->cp0_badvaddr = regs->cp0_badvaddr;
	core->ti_mips->gpregs->cp0_status = regs->cp0_status;
	core->ti_mips->gpregs->cp0_cause = regs->cp0_cause;

	core->ti_mips->fpregs->r0 = fpregs->regs[0];
	core->ti_mips->fpregs->r1 = fpregs->regs[1];
	core->ti_mips->fpregs->r2 = fpregs->regs[2];
	core->ti_mips->fpregs->r3 = fpregs->regs[3];
	core->ti_mips->fpregs->r4 = fpregs->regs[4];
	core->ti_mips->fpregs->r5 = fpregs->regs[5];
	core->ti_mips->fpregs->r6 = fpregs->regs[6];
	core->ti_mips->fpregs->r7 = fpregs->regs[7];
	core->ti_mips->fpregs->r8 = fpregs->regs[8];
	core->ti_mips->fpregs->r9 = fpregs->regs[9];
	core->ti_mips->fpregs->r10 = fpregs->regs[10];
	core->ti_mips->fpregs->r11 = fpregs->regs[11];
	core->ti_mips->fpregs->r12 = fpregs->regs[12];
	core->ti_mips->fpregs->r13 = fpregs->regs[13];
	core->ti_mips->fpregs->r14 = fpregs->regs[14];
	core->ti_mips->fpregs->r15 = fpregs->regs[15];
	core->ti_mips->fpregs->r16 = fpregs->regs[16];
	core->ti_mips->fpregs->r17 = fpregs->regs[17];
	core->ti_mips->fpregs->r18 = fpregs->regs[18];
	core->ti_mips->fpregs->r19 = fpregs->regs[19];
	core->ti_mips->fpregs->r20 = fpregs->regs[20];
	core->ti_mips->fpregs->r21 = fpregs->regs[21];
	core->ti_mips->fpregs->r22 = fpregs->regs[22];
	core->ti_mips->fpregs->r23 = fpregs->regs[23];
	core->ti_mips->fpregs->r24 = fpregs->regs[24];
	core->ti_mips->fpregs->r25 = fpregs->regs[25];
	core->ti_mips->fpregs->r26 = fpregs->regs[26];
	core->ti_mips->fpregs->r27 = fpregs->regs[27];
	core->ti_mips->fpregs->r28 = fpregs->regs[28];
	core->ti_mips->fpregs->r29 = fpregs->regs[29];
	core->ti_mips->fpregs->r30 = fpregs->regs[30];
	core->ti_mips->fpregs->r31 = fpregs->regs[31];
	core->ti_mips->fpregs->fpu_fcr31 = fpregs->fpu_fcr31;
	core->ti_mips->fpregs->fpu_id = fpregs->fpu_id;

	return 0;
}

int arch_alloc_thread_info(CoreEntry *core)
{
	ThreadInfoMips *ti_mips;
	UserMipsRegsEntry *gpregs;
	UserMipsFpregsEntry *fpregs;

	ti_mips = xmalloc(sizeof(*ti_mips));
	if (!ti_mips)
		goto err;

	thread_info_mips__init(ti_mips);
	core->ti_mips = ti_mips;

	gpregs = xmalloc(sizeof(*gpregs));
	if (!gpregs) {
		xfree(ti_mips);
		goto err;
	}

	user_mips_regs_entry__init(gpregs);
	ti_mips->gpregs = gpregs;

	fpregs = xmalloc(sizeof(*fpregs));
	if (!fpregs) {
		xfree(ti_mips);
		xfree(gpregs);
		goto err;
	}

	user_mips_fpregs_entry__init(fpregs);
	ti_mips->fpregs = fpregs;

	return 0;
err:
	return -1;
}

void arch_free_thread_info(CoreEntry *core)
{
	if (!core->ti_mips)
		return;

	if (core->ti_mips->gpregs)
		xfree(core->ti_mips->gpregs);

	if (core->ti_mips->fpregs)
		xfree(core->ti_mips->fpregs);

	xfree(core->ti_mips);
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core)
{
	struct rt_sigframe *f = sigframe;
	UserMipsFpregsEntry *r = core->ti_mips->fpregs;

	f->rs_uc.uc_mcontext.sc_fpregs[0] = r->r0;
	f->rs_uc.uc_mcontext.sc_fpregs[1] = r->r1;
	f->rs_uc.uc_mcontext.sc_fpregs[2] = r->r2;
	f->rs_uc.uc_mcontext.sc_fpregs[3] = r->r3;
	f->rs_uc.uc_mcontext.sc_fpregs[4] = r->r4;
	f->rs_uc.uc_mcontext.sc_fpregs[5] = r->r5;
	f->rs_uc.uc_mcontext.sc_fpregs[6] = r->r6;
	f->rs_uc.uc_mcontext.sc_fpregs[7] = r->r7;
	f->rs_uc.uc_mcontext.sc_fpregs[8] = r->r8;
	f->rs_uc.uc_mcontext.sc_fpregs[9] = r->r9;
	f->rs_uc.uc_mcontext.sc_fpregs[10] = r->r10;
	f->rs_uc.uc_mcontext.sc_fpregs[11] = r->r11;
	f->rs_uc.uc_mcontext.sc_fpregs[12] = r->r12;
	f->rs_uc.uc_mcontext.sc_fpregs[13] = r->r13;
	f->rs_uc.uc_mcontext.sc_fpregs[14] = r->r14;
	f->rs_uc.uc_mcontext.sc_fpregs[15] = r->r15;
	f->rs_uc.uc_mcontext.sc_fpregs[16] = r->r16;
	f->rs_uc.uc_mcontext.sc_fpregs[17] = r->r17;
	f->rs_uc.uc_mcontext.sc_fpregs[18] = r->r18;
	f->rs_uc.uc_mcontext.sc_fpregs[19] = r->r19;
	f->rs_uc.uc_mcontext.sc_fpregs[20] = r->r20;
	f->rs_uc.uc_mcontext.sc_fpregs[21] = r->r21;
	f->rs_uc.uc_mcontext.sc_fpregs[22] = r->r22;
	f->rs_uc.uc_mcontext.sc_fpregs[23] = r->r23;
	f->rs_uc.uc_mcontext.sc_fpregs[24] = r->r24;
	f->rs_uc.uc_mcontext.sc_fpregs[25] = r->r25;
	f->rs_uc.uc_mcontext.sc_fpregs[26] = r->r26;
	f->rs_uc.uc_mcontext.sc_fpregs[27] = r->r27;
	f->rs_uc.uc_mcontext.sc_fpregs[28] = r->r28;
	f->rs_uc.uc_mcontext.sc_fpregs[29] = r->r29;
	f->rs_uc.uc_mcontext.sc_fpregs[30] = r->r30;
	f->rs_uc.uc_mcontext.sc_fpregs[31] = r->r31;

	return 0;
}

int restore_gpregs(struct rt_sigframe *f, UserMipsRegsEntry *r)
{
	f->rs_uc.uc_mcontext.sc_regs[0] = r->r0;
	f->rs_uc.uc_mcontext.sc_regs[1] = r->r1;
	f->rs_uc.uc_mcontext.sc_regs[2] = r->r2;
	f->rs_uc.uc_mcontext.sc_regs[3] = r->r3;
	f->rs_uc.uc_mcontext.sc_regs[4] = r->r4;
	f->rs_uc.uc_mcontext.sc_regs[5] = r->r5;
	f->rs_uc.uc_mcontext.sc_regs[6] = r->r6;
	f->rs_uc.uc_mcontext.sc_regs[7] = r->r7;
	f->rs_uc.uc_mcontext.sc_regs[8] = r->r8;
	f->rs_uc.uc_mcontext.sc_regs[9] = r->r9;
	f->rs_uc.uc_mcontext.sc_regs[10] = r->r10;
	f->rs_uc.uc_mcontext.sc_regs[11] = r->r11;
	f->rs_uc.uc_mcontext.sc_regs[12] = r->r12;
	f->rs_uc.uc_mcontext.sc_regs[13] = r->r13;
	f->rs_uc.uc_mcontext.sc_regs[14] = r->r14;
	f->rs_uc.uc_mcontext.sc_regs[15] = r->r15;
	f->rs_uc.uc_mcontext.sc_regs[16] = r->r16;
	f->rs_uc.uc_mcontext.sc_regs[17] = r->r17;
	f->rs_uc.uc_mcontext.sc_regs[18] = r->r18;
	f->rs_uc.uc_mcontext.sc_regs[19] = r->r19;
	f->rs_uc.uc_mcontext.sc_regs[20] = r->r20;
	f->rs_uc.uc_mcontext.sc_regs[21] = r->r21;
	f->rs_uc.uc_mcontext.sc_regs[22] = r->r22;
	f->rs_uc.uc_mcontext.sc_regs[23] = r->r23;
	f->rs_uc.uc_mcontext.sc_regs[24] = r->r24;
	f->rs_uc.uc_mcontext.sc_regs[25] = r->r25;
	f->rs_uc.uc_mcontext.sc_regs[26] = r->r26;
	f->rs_uc.uc_mcontext.sc_regs[27] = r->r27;
	f->rs_uc.uc_mcontext.sc_regs[28] = r->r28;
	f->rs_uc.uc_mcontext.sc_regs[29] = r->r29;
	f->rs_uc.uc_mcontext.sc_regs[30] = r->r30;
	f->rs_uc.uc_mcontext.sc_regs[31] = r->r31;

	f->rs_uc.uc_mcontext.sc_mdlo = r->lo;
	f->rs_uc.uc_mcontext.sc_mdhi = r->hi;
	f->rs_uc.uc_mcontext.sc_pc = r->cp0_epc;

	return 0;
}

int get_task_futex_robust_list_compat(pid_t pid, ThreadCoreEntry *info)
{
	return 0;
}
