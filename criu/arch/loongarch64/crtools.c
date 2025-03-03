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
#include "asm/restorer.h"
#include "asm/parasite-syscall.h"
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

#define assign_reg(dst, src, e) (dst)->e = (__typeof__(dst->e))(src)->e

int save_task_regs(pid_t pid, void *x, user_regs_struct_t *regs, user_fpregs_struct_t *fpregs)
{
	int i;
	CoreEntry *core = x;
	UserLoongarch64GpregsEntry *gprs = core->ti_loongarch64->gpregs;
	UserLoongarch64FpregsEntry *fprs = core->ti_loongarch64->fpregs;
	for (i = 0; i < GPR_NUM; i++)
		assign_reg(gprs, regs, regs[i]);
	assign_reg(gprs, regs, pc);

	for (i = 0; i < FPR_NUM; i++)
		assign_reg(fpregs, fpregs, regs[i]);
	assign_reg(fprs, fpregs, fcc);
	assign_reg(fprs, fpregs, fcsr);
	return 0;
}

int arch_alloc_thread_info(CoreEntry *core)
{
	ThreadInfoLoongarch64 *ti_loongarch64;
	UserLoongarch64GpregsEntry *gpregs;
	UserLoongarch64FpregsEntry *fpregs;

	ti_loongarch64 = xmalloc(sizeof(*ti_loongarch64));
	thread_info_loongarch64__init(ti_loongarch64);
	core->ti_loongarch64 = ti_loongarch64;

	gpregs = xmalloc(sizeof(*gpregs));
	if (!gpregs)
		goto err;
	user_loongarch64_gpregs_entry__init(gpregs);
	gpregs->n_regs = GPR_NUM;
	gpregs->regs = xmalloc(GPR_NUM * sizeof(uint64_t));
	if (!gpregs->regs)
		goto err;
	ti_loongarch64->gpregs = gpregs;

	fpregs = xmalloc(sizeof(*fpregs));
	if (!fpregs)
		goto err;
	user_loongarch64_fpregs_entry__init(fpregs);
	fpregs->n_regs = FPR_NUM;
	fpregs->regs = xmalloc(FPR_NUM * sizeof(uint64_t));
	if (!fpregs->regs)
		goto err;
	ti_loongarch64->fpregs = fpregs;

	return 0;
err:
	return -1;
}

void arch_free_thread_info(CoreEntry *core)
{
	if (CORE_THREAD_ARCH_INFO(core)) {
		if (CORE_THREAD_ARCH_INFO(core)->fpregs) {
			xfree(CORE_THREAD_ARCH_INFO(core)->fpregs->regs);
			xfree(CORE_THREAD_ARCH_INFO(core)->fpregs);
		}
		xfree(CORE_THREAD_ARCH_INFO(core)->gpregs->regs);
		xfree(CORE_THREAD_ARCH_INFO(core)->gpregs);
		xfree(CORE_THREAD_ARCH_INFO(core));
		CORE_THREAD_ARCH_INFO(core) = NULL;
	}
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core)
{
	fpu_context_t *fpu = RT_SIGFRAME_FPU(sigframe);
	UserLoongarch64FpregsEntry *fpregs = core->ti_loongarch64->fpregs;

	memcpy(fpu->regs, fpregs->regs, sizeof(fpu->regs));
	fpu->fcc = fpregs->fcc;
	fpu->fcsr = fpregs->fcsr;
	return 0;
}

int restore_gpregs(struct rt_sigframe *sigframe, UserRegsEntry *r)
{
	sigcontext_t *sc = RT_SIGFRAME_SIGCTX(sigframe);
	memcpy(sc->regs, r->regs, sizeof(sc->regs));
	sc->pc = r->pc;
	return 0;
}
