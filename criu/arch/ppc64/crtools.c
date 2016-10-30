#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <sys/user.h>
#include <asm/unistd.h>
#include <sys/uio.h>

#include "asm/types.h"
#include "asm/fpu.h"
#include "asm/restorer.h"

#include "cr_options.h"
#include "common/compiler.h"
#include "ptrace.h"
#include "parasite-syscall.h"
#include "log.h"
#include "util.h"
#include "cpu.h"
#include "errno.h"

#include "protobuf.h"
#include "images/core.pb-c.h"
#include "images/creds.pb-c.h"

#define MSR_TMA (1UL<<34)	/* bit 29 Trans Mem state: Transactional */
#define MSR_TMS (1UL<<33)	/* bit 30 Trans Mem state: Suspended */
#define MSR_TM  (1UL<<32)	/* bit 31 Trans Mem Available */
#define MSR_VEC (1UL<<25)
#define MSR_VSX (1UL<<23)

#define MSR_TM_ACTIVE(x) ((((x) & MSR_TM) && ((x)&(MSR_TMA|MSR_TMS))) != 0)

#ifndef NT_PPC_TM_SPR
#define NT_PPC_TM_CGPR  0x108           /* TM checkpointed GPR Registers */
#define NT_PPC_TM_CFPR  0x109           /* TM checkpointed FPR Registers */
#define NT_PPC_TM_CVMX  0x10a           /* TM checkpointed VMX Registers */
#define NT_PPC_TM_CVSX  0x10b           /* TM checkpointed VSX Registers */
#define NT_PPC_TM_SPR   0x10c           /* TM Special Purpose Registers */
#endif


/*
 * Injected syscall instruction
 */
const u32 code_syscall[] = {
	0x44000002,		/* sc 		*/
	0x0fe00000		/* twi 31,0,0	*/
};

static inline void __always_unused __check_code_syscall(void)
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

bool arch_can_dump_task(struct parasite_ctl *ctl)
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

static UserPpc64FpstateEntry *copy_fp_regs(uint64_t *fpregs)
{
	UserPpc64FpstateEntry *fpe;
	int i;

	fpe = xmalloc(sizeof(UserPpc64FpstateEntry));
	if (!fpe)
		return NULL;
	user_ppc64_fpstate_entry__init(fpe);

	fpe->n_fpregs = NFPREG;
	fpe->fpregs = xmalloc(fpe->n_fpregs * sizeof(fpe->fpregs[0]));
	if (!fpe->fpregs) {
		xfree(fpe);
		return NULL;
	}

	/* FPSRC is the last (33th) register in the set */
	for (i = 0; i < NFPREG; i++)
		fpe->fpregs[i] = fpregs[i];

	return fpe;
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
 *
 * There 32 VSX double word registers to save since the 32 first VSX double
 * word registers are saved through FPR[0..32] and the remaining registers
 * are saved when saving the Altivec registers VR[0..32].
 */

static int get_fpu_regs(pid_t pid, user_fpregs_struct_t *fp)
{
	if (ptrace(PTRACE_GETFPREGS, pid, 0, (void *)&fp->fpregs) < 0) {
		pr_perror("Couldn't get floating-point registers");
		return -1;
	}
	fp->flags |= USER_FPREGS_FL_FP;

	return 0;
}

static void put_fpu_regs(mcontext_t *mc, UserPpc64FpstateEntry *fpe)
{
	int i;
	uint64_t *mcfp = (uint64_t *)mc->fp_regs;

	for (i = 0; i < fpe->n_fpregs; i++)
		mcfp[i] =  fpe->fpregs[i];
}

static UserPpc64VrstateEntry *copy_altivec_regs(__vector128 *vrregs)
{
	UserPpc64VrstateEntry *vse;
	uint64_t *p64;
	uint32_t *p32;
	int i;

	vse = xmalloc(sizeof(*vse));
	if (!vse)
		return NULL;
	user_ppc64_vrstate_entry__init(vse);

	/* protocol buffer store only 64bit entries and we need 128bit */
	vse->n_vrregs = (NVRREG-1) * 2;
	vse->vrregs = xmalloc(vse->n_vrregs * sizeof(vse->vrregs[0]));
	if (!vse->vrregs) {
		xfree(vse);
		return NULL;
	}

	/* Vectors are 2*64bits entries */
	for (i = 0; i < (NVRREG-1); i++) {
		p64 = (uint64_t*) &vrregs[i];
		vse->vrregs[i*2] =  p64[0];
		vse->vrregs[i*2 + 1] = p64[1];
	}

	p32 = (uint32_t*) &vrregs[NVRREG-1];
	vse->vrsave = *p32;

	return vse;
}

static int get_altivec_regs(pid_t pid, user_fpregs_struct_t *fp)
{
	if (ptrace(PTRACE_GETVRREGS, pid, 0, (void*)&fp->vrregs) < 0) {
		/* PTRACE_GETVRREGS returns EIO if Altivec is not supported.
		 * This should not happen if msr_vec is set. */
		if (errno != EIO) {
			pr_perror("Couldn't get Altivec registers");
			return -1;
		}
		pr_debug("Altivec not supported\n");
	}
	else {
		pr_debug("Dumping Altivec registers\n");
		fp->flags |= USER_FPREGS_FL_ALTIVEC;
	}
	return 0;
}

static int put_altivec_regs(mcontext_t *mc, UserPpc64VrstateEntry *vse)
{
	vrregset_t *v_regs = (vrregset_t *)(((unsigned long)mc->vmx_reserve + 15) & ~0xful);

	pr_debug("Restoring Altivec registers\n");

	if (vse->n_vrregs != (NVRREG-1)*2) {
		pr_err("Corrupted Altivec dump data\n");
		return -1;
	}

	/* Note that this should only be done in the case MSR_VEC is set but
	 * this is not a big deal to do that in all cases.
	 */
	memcpy(&v_regs->vrregs[0][0], vse->vrregs,
	       sizeof(uint64_t) * 2 * (NVRREG-1));
	/* vscr has been restored with the previous memcpy which copied 32
	 * 128bits registers + a 128bits field containing the vscr value in
	 * the low part.
	 */

	v_regs->vrsave = vse->vrsave;
	mc->v_regs = v_regs;

	return 0;
}

static UserPpc64VsxstateEntry* copy_vsx_regs(uint64_t *vsregs)
{
	UserPpc64VsxstateEntry *vse;
	int i;

	vse = xmalloc(sizeof(*vse));
	if (!vse)
		return NULL;

	user_ppc64_vsxstate_entry__init(vse);
	vse->n_vsxregs = NVSXREG;

	vse->vsxregs = xmalloc(vse->n_vsxregs*sizeof(vse->vsxregs[0]));
	if (!vse->vsxregs) {
		xfree(vse);
		return NULL;
	}

	for (i = 0; i < vse->n_vsxregs; i++)
		vse->vsxregs[i] = vsregs[i];

	return vse;
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
static int get_vsx_regs(pid_t pid, user_fpregs_struct_t *fp)
{
	if (ptrace(PTRACE_GETVSRREGS, pid, 0, (void*)fp->vsxregs) < 0) {
		/*
		 * EIO is returned in the case PTRACE_GETVRREGS is not
		 * supported.
		 */
		if (errno != EIO) {
			pr_perror("Couldn't get VSX registers");
			return -1;
		}
		pr_debug("VSX register's dump not supported.\n");
	}
	else {
		pr_debug("Dumping VSX registers\n");
		fp->flags |= USER_FPREGS_FL_VSX;
	}
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
	for (i=0; i < vse->n_vsxregs; i++)
		buf[i] = vse->vsxregs[i];

	return 0;
}


static void copy_gp_regs(UserPpc64RegsEntry *dst, user_regs_struct_t *src)
{
	int i;

#define assign_reg(e) do {			\
	dst->e = (__typeof__(dst->e))src->e;	\
} while (0)

	for (i=0; i<32; i++)
		assign_reg(gpr[i]);
	assign_reg(nip);
	assign_reg(msr);
	assign_reg(orig_gpr3);
	assign_reg(ctr);
	assign_reg(link);
	assign_reg(xer);
	assign_reg(ccr);
	assign_reg(trap);
#undef assign_reg
}

static void restore_gp_regs(mcontext_t *dst, UserPpc64RegsEntry *src)
{
	int i;

	/* r0 to r31 */
	for (i=0; i<32; i++)
		dst->gp_regs[i] 	= src->gpr[i];

	dst->gp_regs[PT_NIP] 		= src->nip;
	dst->gp_regs[PT_MSR] 		= src->msr;
	dst->gp_regs[PT_ORIG_R3]	= src->orig_gpr3;
	dst->gp_regs[PT_CTR] 		= src->ctr;
	dst->gp_regs[PT_LNK] 		= src->link;
	dst->gp_regs[PT_XER] 		= src->xer;
	dst->gp_regs[PT_CCR] 		= src->ccr;
	dst->gp_regs[PT_TRAP] 		= src->trap;
}

static UserPpc64RegsEntry *allocate_gp_regs(void)
{
	UserPpc64RegsEntry *gpregs;

	gpregs = xmalloc(sizeof(*gpregs));
	if (!gpregs)
		return NULL;
	user_ppc64_regs_entry__init(gpregs);

	gpregs->n_gpr = 32;
	gpregs->gpr = xmalloc(32 * sizeof(uint64_t));
	if (!gpregs->gpr) {
		xfree(gpregs);
		return NULL;
	}

	return gpregs;
}

/****************************************************************************
 * TRANSACTIONAL MEMORY SUPPORT
 */
static void xfree_tm_state(UserPpc64TmRegsEntry *tme)
{
	if (tme) {
		if (tme->fpstate) {
			xfree(tme->fpstate->fpregs);
			xfree(tme->fpstate);
		}
		if (tme->vrstate) {
			xfree(tme->vrstate->vrregs);
			xfree(tme->vrstate);
		}
		if (tme->vsxstate) {
			xfree(tme->vsxstate->vsxregs);
			xfree(tme->vsxstate);
		}
                if (tme->gpregs) {
			if (tme->gpregs->gpr)
				xfree(tme->gpregs->gpr);
			xfree(tme->gpregs);
		}
		xfree(tme);
	}
}

static int get_tm_regs(pid_t pid, user_fpregs_struct_t *fpregs)
{
	struct iovec iov;

	pr_debug("Dumping TM registers\n");

#define TM_REQUIRED	0
#define TM_OPTIONAL	1
#define PTRACE_GET_TM(s,n,c,u) do {					\
	iov.iov_base = &s;						\
	iov.iov_len = sizeof(s);					\
	if (ptrace(PTRACE_GETREGSET, pid, c, &iov)) {			\
		if (!u || errno != EIO) {				\
			pr_perror("Couldn't get TM "n);			\
			pr_err("Your kernel seems to not support the "	\
			       "new TM ptrace API (>= 4.8)\n");		\
			goto out_free;					\
		}							\
		pr_debug("TM "n" not supported.\n");			\
		iov.iov_base = NULL;					\
	}								\
} while(0)

	/* Get special registers */
	PTRACE_GET_TM(fpregs->tm.tm_spr_regs, "SPR", NT_PPC_TM_SPR, TM_REQUIRED);

	/* Get checkpointed regular registers */
	PTRACE_GET_TM(fpregs->tm.regs, "GPR", NT_PPC_TM_CGPR, TM_REQUIRED);

	/* Get checkpointed FP registers */
	PTRACE_GET_TM(fpregs->tm.fpregs, "FPR", NT_PPC_TM_CFPR, TM_OPTIONAL);
	if (iov.iov_base)
		fpregs->tm.flags |= USER_FPREGS_FL_FP;

	/* Get checkpointed VMX (Altivec) registers */
	PTRACE_GET_TM(fpregs->tm.vrregs, "VMX", NT_PPC_TM_CVMX, TM_OPTIONAL);
	if (iov.iov_base)
		fpregs->tm.flags |= USER_FPREGS_FL_ALTIVEC;

	/* Get checkpointed VSX registers */
	PTRACE_GET_TM(fpregs->tm.vsxregs, "VSX", NT_PPC_TM_CVSX, TM_OPTIONAL);
	if (iov.iov_base)
		fpregs->tm.flags |= USER_FPREGS_FL_VSX;

	return 0;

out_free:
	return -1;	/* still failing the checkpoint */
}

static int put_tm_regs(struct rt_sigframe *f, UserPpc64TmRegsEntry *tme)
{
/*
 * WARNING: As stated in kernel's restore_tm_sigcontexts, TEXASR has to be
 * restored by the process itself :
 *   TEXASR was set by the signal delivery reclaim, as was TFIAR.
 *   Users doing anything abhorrent like thread-switching w/ signals for
 *   TM-Suspended code will have to back TEXASR/TFIAR up themselves.
 *   For the case of getting a signal and simply returning from it,
 *   we don't need to re-copy them here.
 */
	struct ucontext *tm_uc = &f->uc_transact;

	pr_debug("Restoring TM registers FP:%d VR:%d VSX:%d\n",
		 !!(tme->fpstate), !!(tme->vrstate), !!(tme->vsxstate));

	restore_gp_regs(&tm_uc->uc_mcontext, tme->gpregs);

	if (tme->fpstate)
		put_fpu_regs(&tm_uc->uc_mcontext, tme->fpstate);

	if (tme->vrstate && put_altivec_regs(&tm_uc->uc_mcontext,
					     tme->vrstate))
		return -1;

	if (tme->vsxstate && put_vsx_regs(&tm_uc->uc_mcontext,
					  tme->vsxstate))
		return -1;

	f->uc.uc_link = tm_uc;
	return 0;
}

/****************************************************************************/
static int __get_task_regs(pid_t pid, user_regs_struct_t *regs,
			   user_fpregs_struct_t *fpregs)
{
	pr_info("Dumping GP/FPU registers for %d\n", pid);

	/*
	 * This is inspired by kernel function check_syscall_restart in
	 * arch/powerpc/kernel/signal.c
	 */
#ifndef TRAP
#define TRAP(r)              ((r).trap & ~0xF)
#endif

	if (TRAP(*regs) == 0x0C00 && regs->ccr & 0x10000000) {
		/* Restart the system call */
		switch (regs->gpr[3]) {
		case ERESTARTNOHAND:
		case ERESTARTSYS:
		case ERESTARTNOINTR:
			regs->gpr[3] = regs->orig_gpr3;
			regs->nip -= 4;
			break;
		case ERESTART_RESTARTBLOCK:
			regs->gpr[0] = __NR_restart_syscall;
			regs->nip -= 4;
			break;
		}
	}

	/* Resetting trap since we are now coming from user space. */
	regs->trap = 0;

	fpregs->flags = 0;
	/*
	 * Check for Transactional Memory operation in progress.
	 * Until we have support of TM register's state through the ptrace API,
	 * we can't checkpoint process with TM operation in progress (almost
	 * impossible) or suspended (easy to get).
	 */
	if (MSR_TM_ACTIVE(regs->msr)) {
		pr_debug("Task %d has %s TM operation at 0x%lx\n",
			 pid,
			 (regs->msr & MSR_TMS) ? "a suspended" : "an active",
			 regs->nip);
		if (get_tm_regs(pid, fpregs))
			return -1;
		fpregs->flags = USER_FPREGS_FL_TM;
	}

	if (get_fpu_regs(pid, fpregs))
		return -1;

	if (get_altivec_regs(pid, fpregs))
		return -1;

	if (fpregs->flags & USER_FPREGS_FL_ALTIVEC) {
		/*
		 * Save the VSX registers if Altivec registers are supported
		 */
		if (get_vsx_regs(pid, fpregs))
			return -1;
	}
	return 0;
}

static int copy_tm_regs(user_regs_struct_t *regs, user_fpregs_struct_t *fpregs,
			CoreEntry *core)
{
	UserPpc64TmRegsEntry *tme;
        UserPpc64RegsEntry *gpregs = core->ti_ppc64->gpregs;

	pr_debug("Copying TM registers\n");
	        tme = xmalloc(sizeof(*tme));
        if (!tme)
                return -1;

	user_ppc64_tm_regs_entry__init(tme);

        tme->gpregs = allocate_gp_regs();
        if (!tme->gpregs)
                goto out_free;

        gpregs->has_tfhar       = true;
        gpregs->tfhar           = fpregs->tm.tm_spr_regs.tfhar;
        gpregs->has_texasr      = true;
        gpregs->texasr          = fpregs->tm.tm_spr_regs.texasr;
        gpregs->has_tfiar       = true;
        gpregs->tfiar           = fpregs->tm.tm_spr_regs.tfiar;


	/* This is the checkpointed state, we must save it in place of the
	 * current state because the signal handler is made in this way.
	 * We invert the 2 states instead of when building the signal frame,
	 * because we can't modify the gpregs manipulated by the common layer.
	 */
	copy_gp_regs(gpregs, &fpregs->tm.regs);

	if (fpregs->tm.flags & USER_FPREGS_FL_FP) {
                core->ti_ppc64->fpstate = copy_fp_regs(fpregs->tm.fpregs);
                if (!core->ti_ppc64->fpstate)
                        goto out_free;
        }

	if (fpregs->tm.flags & USER_FPREGS_FL_ALTIVEC) {
                core->ti_ppc64->vrstate = copy_altivec_regs(fpregs->tm.vrregs);
                if (!core->ti_ppc64->vrstate)
                        goto out_free;

                /*
                 * Force the MSR_VEC bit of the restored MSR otherwise the
                 * kernel will not restore them from the signal frame.
                 */
                gpregs->msr |= MSR_VEC;

		if (fpregs->tm.flags & USER_FPREGS_FL_VSX) {
			core->ti_ppc64->vsxstate = copy_vsx_regs(fpregs->tm.vsxregs);
			if (!core->ti_ppc64->vsxstate)
				goto out_free;
			/*
                         * Force the MSR_VSX bit of the restored MSR otherwise
                         * the kernel will not restore them from the signal
                         * frame.
                         */
                        gpregs->msr |= MSR_VSX;
		}
	}

	core->ti_ppc64->tmstate = tme;
	return 0;

out_free:
	xfree_tm_state(tme);
	return -1;
}

static int __copy_task_regs(user_regs_struct_t *regs,
			    user_fpregs_struct_t *fpregs,
			    CoreEntry *core)
{
	UserPpc64RegsEntry *gpregs;
	UserPpc64FpstateEntry **fpstate;
	UserPpc64VrstateEntry **vrstate;
	UserPpc64VsxstateEntry **vsxstate;

	/* Copy retrieved registers in the proto data
	 * If TM is in the loop we switch the saved register set because
	 * the signal frame is built with checkpointed registers on top to not
	 * confused TM unaware process, while ptrace is retrieving the
	 * checkpointed set through the TM specific ELF notes.
	 */
	if (fpregs->flags & USER_FPREGS_FL_TM) {
		if (copy_tm_regs(regs, fpregs, core))
			return -1;
		gpregs = core->ti_ppc64->tmstate->gpregs;
		fpstate = &(core->ti_ppc64->tmstate->fpstate);
		vrstate = &(core->ti_ppc64->tmstate->vrstate);
		vsxstate = &(core->ti_ppc64->tmstate->vsxstate);
	}
	else {
		gpregs = core->ti_ppc64->gpregs;
		fpstate = &(core->ti_ppc64->fpstate);
		vrstate = &(core->ti_ppc64->vrstate);
		vsxstate = &(core->ti_ppc64->vsxstate);
        }

	copy_gp_regs(gpregs, regs);
	if (fpregs->flags & USER_FPREGS_FL_FP) {
		*fpstate = copy_fp_regs(fpregs->fpregs);
		if (!*fpstate)
			return -1;
	}
	if (fpregs->flags & USER_FPREGS_FL_ALTIVEC) {
		*vrstate = copy_altivec_regs(fpregs->vrregs);
		if (!*vrstate)
			return -1;
                /*
                 * Force the MSR_VEC bit of the restored MSR otherwise the
                 * kernel will not restore them from the signal frame.
                 */
                gpregs->msr |= MSR_VEC;

		if (fpregs->flags & USER_FPREGS_FL_VSX) {
			*vsxstate = copy_vsx_regs(fpregs->vsxregs);
			if (!*vsxstate)
				return -1;
                        /*
                         * Force the MSR_VSX bit of the restored MSR otherwise
                         * the kernel will not restore them from the signal
                         * frame.
                         */
                        gpregs->msr |= MSR_VSX;
		}
	}
	return 0;
}


/****************************************************************************/
int get_task_regs(pid_t pid, user_regs_struct_t regs, CoreEntry *core)
{
	user_fpregs_struct_t fpregs;
	int ret;

	ret = __get_task_regs(pid, &regs, &fpregs);
	if (ret)
		return ret;

	return __copy_task_regs(&regs, &fpregs, core);
}

int arch_alloc_thread_info(CoreEntry *core)
{
	ThreadInfoPpc64 *ti_ppc64;

	ti_ppc64 = xmalloc(sizeof(*ti_ppc64));
	if(!ti_ppc64)
		return -1;

	thread_info_ppc64__init(ti_ppc64);

	ti_ppc64->gpregs = allocate_gp_regs();
	if (!ti_ppc64->gpregs) {
		xfree(ti_ppc64);
		return -1;
	}

	CORE_THREAD_ARCH_INFO(core) = ti_ppc64;
	return 0;
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
		xfree_tm_state(CORE_THREAD_ARCH_INFO(core)->tmstate);
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
		pr_err("Register's data mismatch, corrupted image ?\n");
		ret = -1;
	}

	if (!ret && CORE_THREAD_ARCH_INFO(core)->vsxstate)
		ret = put_vsx_regs(&sigframe->uc.uc_mcontext,
				   CORE_THREAD_ARCH_INFO(core)->vsxstate);
	else if (core->ti_ppc64->gpregs->msr & MSR_VSX) {
		pr_err("VSX register's data mismatch, corrupted image ?\n");
		ret = -1;
	}

	if (!ret && CORE_THREAD_ARCH_INFO(core)->tmstate)
		ret = put_tm_regs(sigframe,
				  CORE_THREAD_ARCH_INFO(core)->tmstate);
	else if (MSR_TM_ACTIVE(core->ti_ppc64->gpregs->msr)) {
		pr_err("TM register's data mismatch, corrupted image ?\n");
		ret = -1;
	}

	return ret;
}

/*
 * The signal frame has been built using local addresses. Since it has to be
 * used in the context of the checkpointed process, the v_regs pointer in the
 * signal frame must be updated to match the address in the remote stack.
 */
static inline void update_vregs(mcontext_t *lcontext, mcontext_t *rcontext)
{
	if (lcontext->v_regs) {
		uint64_t offset = (uint64_t)(lcontext->v_regs) - (uint64_t)lcontext;
		lcontext->v_regs = (vrregset_t *)((uint64_t)rcontext + offset);

		pr_debug("Updated v_regs:%llx (rcontext:%llx)\n",
			 (unsigned long long) lcontext->v_regs,
			 (unsigned long long) rcontext);
	}
}

int sigreturn_prep_fpu_frame(struct rt_sigframe *frame,
			     struct rt_sigframe *rframe)
{
	uint64_t msr = frame->uc.uc_mcontext.gp_regs[PT_MSR];

	update_vregs(&frame->uc.uc_mcontext, &rframe->uc.uc_mcontext);

	/* Sanity check: If TM so uc_link should be set, otherwise not */
	if (MSR_TM_ACTIVE(msr) ^ (!!(frame->uc.uc_link))) {
		BUG();
		return 1;
	}

	/* Updating the transactional state address if any */
	if (frame->uc.uc_link) {
		update_vregs(&frame->uc_transact.uc_mcontext,
			     &rframe->uc_transact.uc_mcontext);
		frame->uc.uc_link =  &rframe->uc_transact;
	}

	return 0;
}

int restore_gpregs(struct rt_sigframe *f, UserPpc64RegsEntry *r)
{
	restore_gp_regs(&f->uc.uc_mcontext, r);

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
