#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <sys/user.h>

#include "asm/types.h"
#include "asm/fpu.h"
#include "asm/restorer.h"

#include "cr_options.h"
#include "compiler.h"
#include "ptrace.h"
#include "parasite-syscall.h"
#include "syscall.h"
#include "log.h"
#include "util.h"
#include "cpu.h"
#include "errno.h"

#include "protobuf.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/creds.pb-c.h"

/*
 * Injected syscall instruction
 */
const u32 code_syscall[] = {
	0x44000002,		/* sc 		*/
	0x0fe00000		/* twi 31,0,0	*/
};

const int code_syscall_size = sizeof(code_syscall);

static inline void __check_code_syscall(void)
{
	BUILD_BUG_ON(sizeof(code_syscall) != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs)
{
	regs->nip = new_ip;
	if (stack)
		regs->gpr[1] = (unsigned long) stack;
	regs->trap = 0;
}

bool arch_can_dump_task(pid_t pid)
{
	/*
	 * TODO: We should detect 32bit task when BE support is done.
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

	regs.gpr[0] = (unsigned long)nr;
	regs.gpr[3] = arg1;
	regs.gpr[4] = arg2;
	regs.gpr[5] = arg3;
	regs.gpr[6] = arg4;
	regs.gpr[7] = arg5;
	regs.gpr[8] = arg6;

	err = __parasite_execute_syscall(ctl, &regs);

	*ret = regs.gpr[3];
	return err;
}

/* This is the layout of the POWER7 VSX registers and the way they
 * overlap with the existing FPR and VMX registers.
 *
 *                 VSR doubleword 0               VSR doubleword 1
 *         ----------------------------------------------------------------
 * VSR[0]  |             FPR[0]            |                              |
 *         ----------------------------------------------------------------
 * VSR[1]  |             FPR[1]            |                              |
 *         ----------------------------------------------------------------
 *         |              ...              |                              |
 *         ----------------------------------------------------------------
 * VSR[30] |             FPR[30]           |                              |
 *         ----------------------------------------------------------------
 * VSR[31] |             FPR[31]           |                              |
 *         ----------------------------------------------------------------
 * VSR[32] |                             VR[0]                            |
 *         ----------------------------------------------------------------
 * VSR[33] |                             VR[1]                            |
 *         ----------------------------------------------------------------
 *         |                              ...                             |
 *         ----------------------------------------------------------------
 * VSR[62] |                             VR[30]                           |
 *         ----------------------------------------------------------------
 * VSR[63] |                             VR[31]                           |
 *         ----------------------------------------------------------------
 *
 * PTRACE_GETFPREGS returns FPR[0..31] + FPSCR
 * PTRACE_GETVRREGS returns VR[0..31] + VSCR + VRSAVE
 * PTRACE_GETVSRREGS returns VSR[0..31]
 *
 * PTRACE_GETVSRREGS and PTRACE_GETFPREGS are required since we need
 * to save FPSCR too.
 */
static int get_fpu_regs(pid_t pid, CoreEntry *core)
{
	elf_fpregset_t fpregs;
	UserPpc64FpstateEntry *fpe;
	int i;

	if (ptrace(PTRACE_GETFPREGS, pid, 0, (void *)&fpregs) < 0) {
		pr_err("Couldn't get floating-point registers.");
		return -1;
	}

	fpe = xmalloc(sizeof(UserPpc64FpstateEntry));
	if (!fpe)
		return -1;
	user_ppc64_fpstate_entry__init(fpe);

	fpe->n_fpregs = NFPREG;
	fpe->fpregs = xmalloc(fpe->n_fpregs * sizeof(fpe->fpregs[0]));
	if (!fpe->fpregs) {
		xfree(fpe);
		return -1;
	}

	/* FPSRC is the last (33th) register in the set */
	for (i=0; i<NFPREG; i++)
		fpe->fpregs[i] = fpregs[i];

	core->ti_ppc64->fpstate = fpe;
	return 0;
}

static void put_fpu_regs(mcontext_t *mc, UserPpc64FpstateEntry *fpe)
{
	int i;

	for (i=0; i<fpe->n_fpregs; i++)
		mc->fp_regs[i] = (double)(fpe->fpregs[i]);
}

int get_task_regs(pid_t pid, user_regs_struct_t regs, CoreEntry *core)
{
	int i;

	pr_info("Dumping GP/FPU registers for %d\n", pid);

	/*
	 * This is inspired by kernel function check_syscall_restart in
	 * arch/powerpc/kernel/signal.c
	 */
#ifndef TRAP
#define TRAP(r)              ((r).trap & ~0xF)
#endif

	if (TRAP(regs) == 0x0C00 && regs.ccr & 0x10000000) {
		/* Restart the system call */
		switch (regs.gpr[3]) {
		case ERESTARTNOHAND:
		case ERESTARTSYS:
		case ERESTARTNOINTR:
			regs.gpr[3] = regs.orig_gpr3;
			regs.nip -= 4;
			break;
		case ERESTART_RESTARTBLOCK:
			regs.gpr[0] = __NR_restart_syscall;
			regs.nip -= 4;
			break;
		}
	}

	/* Resetting trap since we are now comming from user space. */
	regs.trap = 0;

#define assign_reg(dst, src, e) do {			\
		dst->e = (__typeof__(dst->e))src.e;	\
} while (0)

	for (i=0; i<32; i++)
		assign_reg(core->ti_ppc64->gpregs, regs, gpr[i]);

	assign_reg(core->ti_ppc64->gpregs, regs, nip);
	assign_reg(core->ti_ppc64->gpregs, regs, msr);
	assign_reg(core->ti_ppc64->gpregs, regs, orig_gpr3);
	assign_reg(core->ti_ppc64->gpregs, regs, ctr);
	assign_reg(core->ti_ppc64->gpregs, regs, link);
	assign_reg(core->ti_ppc64->gpregs, regs, xer);
	assign_reg(core->ti_ppc64->gpregs, regs, ccr);
	assign_reg(core->ti_ppc64->gpregs, regs, trap);
#undef assign_reg

	if (get_fpu_regs(pid, core))
		return -1;

	return 0;
}

int arch_alloc_thread_info(CoreEntry *core)
{
	ThreadInfoPpc64 *ti_ppc64;
	UserPpc64RegsEntry *regs;

	ti_ppc64 = xmalloc(sizeof(*ti_ppc64));
	if(!ti_ppc64)
		goto err;
	thread_info_ppc64__init(ti_ppc64);
	CORE_THREAD_ARCH_INFO(core) = ti_ppc64;

	/* user_ppc64_regs_entry */
	regs = xmalloc(sizeof(*regs));
	if (!regs)
		goto err;
	user_ppc64_regs_entry__init(regs);

	regs->gpr = xmalloc(32*sizeof(uint64_t));
	if (!regs->gpr)
		goto err;
	regs->n_gpr = 32;

	ti_ppc64->gpregs = regs;

	return 0;
err:
	return -1;
}

void arch_free_thread_info(CoreEntry *core)
{
        if (CORE_THREAD_ARCH_INFO(core)) {
		if (CORE_THREAD_ARCH_INFO(core)->fpstate) {
			xfree(CORE_THREAD_ARCH_INFO(core)->fpstate->fpregs);
			xfree(CORE_THREAD_ARCH_INFO(core)->fpstate);
		}
                xfree(CORE_THREAD_ARCH_INFO(core)->gpregs->gpr);
                xfree(CORE_THREAD_ARCH_INFO(core)->gpregs);
                xfree(CORE_THREAD_ARCH_INFO(core));
                CORE_THREAD_ARCH_INFO(core) = NULL;
        }
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core)
{
	if (CORE_THREAD_ARCH_INFO(core)->fpstate)
		put_fpu_regs(&sigframe->uc.uc_mcontext,
			     CORE_THREAD_ARCH_INFO(core)->fpstate);
	return 0;
}

int restore_gpregs(struct rt_sigframe *f, UserPpc64RegsEntry *r)
{
	int i;

	/* r0 to r31 */
	for (i=0; i<32; i++)
		f->uc.uc_mcontext.gp_regs[i] = r->gpr[i];

	f->uc.uc_mcontext.gp_regs[PT_NIP] = r->nip;
	f->uc.uc_mcontext.gp_regs[PT_MSR] = r->msr;
	f->uc.uc_mcontext.gp_regs[PT_ORIG_R3] = r->orig_gpr3;
	f->uc.uc_mcontext.gp_regs[PT_CTR] = r->ctr;
	f->uc.uc_mcontext.gp_regs[PT_LNK] = r->link;
	f->uc.uc_mcontext.gp_regs[PT_XER] = r->xer;
	f->uc.uc_mcontext.gp_regs[PT_CCR] = r->ccr;
	f->uc.uc_mcontext.gp_regs[PT_TRAP] = r->trap;

	return 0;
}

void *mmap_seized(struct parasite_ctl *ctl,
		  void *addr, size_t length, int prot,
		  int flags, int fd, off_t offset)
{
	unsigned long map = 0;
	int err;

	err = syscall_seized(ctl, __NR_mmap, &map,
			(unsigned long)addr, length, prot, flags, fd, offset);
	if (err < 0 || (long)map < 0)
		map = 0;

	return (void *)map;
}
