#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <sys/user.h>
#include <asm/unistd.h>

#include "asm/types.h"
#include "asm/fpu.h"
#include "asm/restorer.h"

#include "cr_options.h"
#include "compiler.h"
#include "ptrace.h"
#include "parasite-syscall.h"
#include "log.h"
#include "util.h"
#include "cpu.h"
#include "errno.h"

#include "protobuf.h"
#include "images/core.pb-c.h"
#include "images/creds.pb-c.h"

#define MSR_VEC (1<<25)
#define MSR_VSX (1<<23)

/*
 * Injected syscall instruction
 */
const u32 code_syscall[] = {
	0x44000002,		/* sc 		*/
	0x0fe00000		/* twi 31,0,0	*/
};

static inline void __check_code_syscall(void)
{
	BUILD_BUG_ON(sizeof(code_syscall) != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs)
{
	/*
	 * OpenPOWER ABI requires that r12 is set to the calling function addressi
	 * to compute the TOC pointer.
	 */
	regs->gpr[12] = new_ip;
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

	err = __parasite_execute_syscall(ctl, &regs, (char*)code_syscall);

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
	uint64_t fpregs[NFPREG];
	UserPpc64FpstateEntry *fpe;
	int i;

	if (ptrace(PTRACE_GETFPREGS, pid, 0, (void *)&fpregs) < 0) {
		pr_perror("Couldn't get floating-point registers");
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
	for (i = 0; i < NFPREG; i++)
		fpe->fpregs[i] = fpregs[i];

	core->ti_ppc64->fpstate = fpe;
	return 0;
}

static void put_fpu_regs(mcontext_t *mc, UserPpc64FpstateEntry *fpe)
{
	int i;
	uint64_t *mcfp = (uint64_t *)mc->fp_regs;

	for (i = 0; i < fpe->n_fpregs; i++)
		mcfp[i] =  fpe->fpregs[i];
}

static int get_altivec_regs(pid_t pid, CoreEntry *core)
{
	/* The kernel returns :
	 *   32 Vector registers (128bit)
	 *   VSCR (32bit) stored in a 128bit entry (odd)
	 *   VRSAVE (32bit) store at the end.
	 *
	 * Kernel setup_sigcontext's comment mentions:
	 * "Userland shall check AT_HWCAP to know whether it can rely on the
	 * v_regs pointer or not"
	 */
	unsigned char vrregs[33 * 16 + 4];
	UserPpc64VrstateEntry *vse;
	uint64_t *p64;
	uint32_t *p32;
	int i;

	if (ptrace(PTRACE_GETVRREGS, pid, 0, (void*)&vrregs) < 0) {
		/* PTRACE_GETVRREGS returns EIO if Altivec is not supported.
		 * This should not happen if msr_vec is set. */
		if (errno != EIO) {
			pr_perror("Couldn't get Altivec registers");
			return -1;
		}
		pr_debug("Altivec not supported\n");
		return 0;
	}

	pr_debug("Dumping Altivec registers\n");

	vse = xmalloc(sizeof(*vse));
	if (!vse)
		return -1;
	user_ppc64_vrstate_entry__init(vse);

	vse->n_vrregs = 33 * 2; /* protocol buffer store 64bit entries */
	vse->vrregs = xmalloc(vse->n_vrregs * sizeof(vse->vrregs[0]));
	if (!vse->vrregs) {
		xfree(vse);
		return -1;
	}

	/* Vectors are 2*64bits entries */
	for (i = 0; i < 33; i++) {
		p64 = (uint64_t*) &vrregs[i * 2 * sizeof(uint64_t)];
		vse->vrregs[i*2] =  p64[0];
		vse->vrregs[i*2 + 1] = p64[1];
	}

	p32 = (uint32_t*) &vrregs[33 * 2 * sizeof(uint64_t)];
	vse->vrsave = *p32;

	core->ti_ppc64->vrstate = vse;

	/*
	 * Force the MSR_VEC bit of the restored MSR otherwise the kernel
	 * will not restore them from the signal frame.
	 */
	core->ti_ppc64->gpregs->msr |= MSR_VEC;

	return 0;
}

static int put_altivec_regs(mcontext_t *mc, UserPpc64VrstateEntry *vse)
{
	vrregset_t *v_regs = (vrregset_t *)(((unsigned long)mc->vmx_reserve + 15) & ~0xful);

	pr_debug("Restoring Altivec registers\n");

	if (vse->n_vrregs != 33*2) {
		pr_err("Corrupted Altivec dump data\n");
		return -1;
	}

	/* Note that this should only be done in the case MSR_VEC is set but
	 * this is not a big deal to do that in all cases.
	 */
	memcpy(&v_regs->vrregs[0][0], vse->vrregs, sizeof(uint64_t) * 2 * 33);
	/* vscr has been restored with the previous memcpy which copied 32
	 * 128bits registers + a 128bits field containing the vscr value in
	 * the low part.
	 */

	v_regs->vrsave = vse->vrsave;
	mc->v_regs = v_regs;

	return 0;
}

/*
 * Since the FPR[0-31] is stored in the first double word of VSR[0-31] and
 * FPR are saved through the FP state, there is no need to save the upper part
 * of the first 32 VSX registers.
 * Furthermore, the 32 last VSX registers are also the 32 Altivec registers
 * already saved, so no need to save them.
 * As a consequence, only the doubleword 1 of the 32 first VSX registers have
 * to be saved (the ones are returned by PTRACE_GETVSRREGS).
 */
static int get_vsx_regs(pid_t pid, CoreEntry *core)
{
	UserPpc64VsxstateEntry *vse;
	uint64_t vsregs[32];
	int i;

	if (ptrace(PTRACE_GETVSRREGS, pid, 0, (void*)&vsregs) < 0) {
		/*
		 * EIO is returned in the case PTRACE_GETVRREGS is not
		 * supported.
		 */
		if (errno == EIO) {
			pr_debug("VSX register's dump not supported.\n");
			return 0;
		}
		pr_perror("Couldn't get VSX registers");
		return -1;
	}

	pr_debug("Dumping VSX registers\n");

	vse = xmalloc(sizeof(*vse));
	if (!vse)
		return -1;
	user_ppc64_vsxstate_entry__init(vse);

	vse->n_vsxregs = 32;
	vse->vsxregs = xmalloc(vse->n_vsxregs * sizeof(vse->vsxregs[0]));
	if (!vse->vsxregs) {
		xfree(vse);
		return -1;
	}

	for (i = 0; i < vse->n_vsxregs; i++)
		vse->vsxregs[i] = vsregs[i];

	core->ti_ppc64->vsxstate = vse;

	/*
	 * Force the MSR_VSX bit of the restored MSR otherwise the kernel
	 * will not restore them from the signal frame.
	 */
	core->ti_ppc64->gpregs->msr |= MSR_VSX;
	return 0;
}

static int put_vsx_regs(mcontext_t *mc, UserPpc64VsxstateEntry *vse)
{
	uint64_t *buf;
	int i;

	pr_debug("Restoring VSX registers\n");
	if (!mc->v_regs) {
		/* VSX implies Altivec so v_regs should be set */
		pr_err("Internal error\n");
		return -1;
	}

	/* point after the Altivec registers */
	buf = (uint64_t*) (mc->v_regs + 1);

	/* Copy the value saved by get_vsx_regs in the sigframe */
	for (i=0; i<vse->n_vsxregs; i++)
		buf[i] = vse->vsxregs[i];

	return 0;
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

	/* Resetting trap since we are now coming from user space. */
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

	if (get_altivec_regs(pid, core))
		return -1;

	/*
	 * Don't save the VSX registers if Altivec registers are not
	 * supported
	 */
	if (CORE_THREAD_ARCH_INFO(core)->vrstate && get_vsx_regs(pid, core))
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
		if (CORE_THREAD_ARCH_INFO(core)->vrstate) {
			xfree(CORE_THREAD_ARCH_INFO(core)->vrstate->vrregs);
			xfree(CORE_THREAD_ARCH_INFO(core)->vrstate);
		}
		if (CORE_THREAD_ARCH_INFO(core)->vsxstate) {
			xfree(CORE_THREAD_ARCH_INFO(core)->vsxstate->vsxregs);
			xfree(CORE_THREAD_ARCH_INFO(core)->vsxstate);
		}
                xfree(CORE_THREAD_ARCH_INFO(core)->gpregs->gpr);
                xfree(CORE_THREAD_ARCH_INFO(core)->gpregs);
                xfree(CORE_THREAD_ARCH_INFO(core));
                CORE_THREAD_ARCH_INFO(core) = NULL;
        }
}

int restore_fpu(struct rt_sigframe *sigframe, CoreEntry *core)
{
	int ret = 0;
	if (CORE_THREAD_ARCH_INFO(core)->fpstate)
		put_fpu_regs(&sigframe->uc.uc_mcontext,
			     CORE_THREAD_ARCH_INFO(core)->fpstate);

	if (CORE_THREAD_ARCH_INFO(core)->vrstate)
		ret = put_altivec_regs(&sigframe->uc.uc_mcontext,
				       CORE_THREAD_ARCH_INFO(core)->vrstate);
	else if (core->ti_ppc64->gpregs->msr & MSR_VEC) {
		pr_err("Internal error\n");
		ret = -1;
	}

	if (!ret && CORE_THREAD_ARCH_INFO(core)->vsxstate)
		ret = put_vsx_regs(&sigframe->uc.uc_mcontext,
				   CORE_THREAD_ARCH_INFO(core)->vsxstate);
	else if (core->ti_ppc64->gpregs->msr & MSR_VSX) {
		pr_err("Internal error\n");
		ret = -1;
	}

	return ret;
}

/*
 * The signal frame has been built using local addresses. Since it has to be
 * used in the context of the checkpointed process, the v_regs pointer in the
 * signal frame must be updated to match the address in the remote stack.
 */
int sigreturn_prep_fpu_frame(struct rt_sigframe *frame, mcontext_t *rcontext)
{
	mcontext_t *lcontext = &frame->uc.uc_mcontext;

	if (lcontext->v_regs) {
		uint64_t offset = (uint64_t)(lcontext->v_regs) - (uint64_t)lcontext;
		lcontext->v_regs = (vrregset_t *)((uint64_t)rcontext + offset);

		pr_debug("Updated v_regs:%llx (rcontext:%llx)\n",
			 (unsigned long long) lcontext->v_regs,
			 (unsigned long long) rcontext);
	}
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
