#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>
#include <compel/plugins/std/syscall-codes.h>
#include "uapi/compel/asm/infect-types.h"
#include "errno.h"
#include "log.h"
#include "common/bug.h"
#include "common/page.h"
#include "infect.h"
#include "infect-priv.h"

#ifndef NT_PPC_TM_SPR
#define NT_PPC_TM_CGPR  0x108           /* TM checkpointed GPR Registers */
#define NT_PPC_TM_CFPR  0x109           /* TM checkpointed FPR Registers */
#define NT_PPC_TM_CVMX  0x10a           /* TM checkpointed VMX Registers */
#define NT_PPC_TM_CVSX  0x10b           /* TM checkpointed VSX Registers */
#define NT_PPC_TM_SPR   0x10c           /* TM Special Purpose Registers */
#endif

unsigned __page_size = 0;
unsigned __page_shift = 0;

/*
 * Injected syscall instruction
 */
const uint32_t code_syscall[] = {
	0x44000002,		/* sc 		*/
	0x0fe00000		/* twi 31,0,0	*/
};

static inline __always_unused void __check_code_syscall(void)
{
	BUILD_BUG_ON(sizeof(code_syscall) != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

static void prep_gp_regs(mcontext_t *dst, user_regs_struct_t *regs)
{
	memcpy(dst->gp_regs, regs->gpr, sizeof(regs->gpr));

	dst->gp_regs[PT_NIP]		= regs->nip;
	dst->gp_regs[PT_MSR]		= regs->msr;
	dst->gp_regs[PT_ORIG_R3]	= regs->orig_gpr3;
	dst->gp_regs[PT_CTR]		= regs->ctr;
	dst->gp_regs[PT_LNK]		= regs->link;
	dst->gp_regs[PT_XER]		= regs->xer;
	dst->gp_regs[PT_CCR]		= regs->ccr;
	dst->gp_regs[PT_TRAP]		= regs->trap;
}

static void put_fpu_regs(mcontext_t *mc, uint64_t *fpregs)
{
	uint64_t *mcfp = (uint64_t *)mc->fp_regs;

	memcpy(mcfp, fpregs, sizeof(*fpregs) * NFPREG);
}

static void put_altivec_regs(mcontext_t *mc, __vector128 *vrregs)
{
	vrregset_t *v_regs = (vrregset_t *)(((unsigned long)mc->vmx_reserve + 15) & ~0xful);

	memcpy(&v_regs->vrregs[0][0], vrregs, sizeof(uint64_t) * 2 * (NVRREG - 1));
	v_regs->vrsave = *((uint32_t *)&vrregs[NVRREG - 1]);
	mc->v_regs = v_regs;
}

static void put_vsx_regs(mcontext_t *mc, uint64_t *vsxregs)
{
	memcpy((uint64_t *)(mc->v_regs + 1), vsxregs, sizeof(*vsxregs) * NVSXREG);
}

int sigreturn_prep_regs_plain(struct rt_sigframe *sigframe,
			      user_regs_struct_t *regs,
			      user_fpregs_struct_t *fpregs)
{
	mcontext_t *dst_tc = &sigframe->uc_transact.uc_mcontext;
	mcontext_t *dst = &sigframe->uc.uc_mcontext;

	if (fpregs->flags & USER_FPREGS_FL_TM) {
		prep_gp_regs(&sigframe->uc_transact.uc_mcontext, &fpregs->tm.regs);
		prep_gp_regs(&sigframe->uc.uc_mcontext, &fpregs->tm.regs);
	} else {
		prep_gp_regs(&sigframe->uc.uc_mcontext, regs);
	}

	if (fpregs->flags & USER_FPREGS_FL_TM)
		sigframe->uc.uc_link = &sigframe->uc_transact;

	if (fpregs->flags & USER_FPREGS_FL_FP) {
		if (fpregs->flags & USER_FPREGS_FL_TM) {
			put_fpu_regs(&sigframe->uc_transact.uc_mcontext, fpregs->tm.fpregs);
			put_fpu_regs(&sigframe->uc.uc_mcontext, fpregs->tm.fpregs);
		} else {
			put_fpu_regs(&sigframe->uc.uc_mcontext, fpregs->fpregs);
		}
	}

	if (fpregs->flags & USER_FPREGS_FL_ALTIVEC) {
		if (fpregs->flags & USER_FPREGS_FL_TM) {
			put_altivec_regs(&sigframe->uc_transact.uc_mcontext, fpregs->tm.vrregs);
			put_altivec_regs(&sigframe->uc.uc_mcontext, fpregs->tm.vrregs);

			dst_tc->gp_regs[PT_MSR] |= MSR_VEC;
		} else {
			put_altivec_regs(&sigframe->uc.uc_mcontext, fpregs->vrregs);
		}

		dst->gp_regs[PT_MSR] |= MSR_VEC;

		if (fpregs->flags & USER_FPREGS_FL_VSX) {
			if (fpregs->flags & USER_FPREGS_FL_TM) {
				put_vsx_regs(&sigframe->uc_transact.uc_mcontext, fpregs->tm.vsxregs);
				put_vsx_regs(&sigframe->uc.uc_mcontext, fpregs->tm.vsxregs);

				dst_tc->gp_regs[PT_MSR] |= MSR_VSX;
			} else {
				put_vsx_regs(&sigframe->uc.uc_mcontext, fpregs->vsxregs);
			}
			dst->gp_regs[PT_MSR] |= MSR_VSX;
		}
	}

	return 0;
}

static void update_vregs(mcontext_t *lcontext, mcontext_t *rcontext)
{
	if (lcontext->v_regs) {
		uint64_t offset = (uint64_t)(lcontext->v_regs) - (uint64_t)lcontext;
		lcontext->v_regs = (vrregset_t *)((uint64_t)rcontext + offset);

		pr_debug("Updated v_regs:%llx (rcontext:%llx)\n",
			 (unsigned long long)lcontext->v_regs,
			 (unsigned long long)rcontext);
	}
}

int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *frame,
				   struct rt_sigframe *rframe)
{
	uint64_t msr = frame->uc.uc_mcontext.gp_regs[PT_MSR];

	update_vregs(&frame->uc.uc_mcontext, &rframe->uc.uc_mcontext);

	/* Sanity check: If TM so uc_link should be set, otherwise not */
	if (MSR_TM_ACTIVE(msr) ^ (!!(frame->uc.uc_link))) {
		BUG();
		return -1;
	}

	/* Updating the transactional state address if any */
	if (frame->uc.uc_link) {
		update_vregs(&frame->uc_transact.uc_mcontext,
			     &rframe->uc_transact.uc_mcontext);
		frame->uc.uc_link =  &rframe->uc_transact;
	}

	return 0;
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

int get_task_regs(pid_t pid, user_regs_struct_t *regs, save_regs_t save,
		  void *arg, __maybe_unused unsigned long flags)
{
	user_fpregs_struct_t fpregs;
	int ret;

	ret = __get_task_regs(pid, regs, &fpregs);
	if (ret)
		return ret;

	return save(arg, regs, &fpregs);
}

int compel_syscall(struct parasite_ctl *ctl, int nr, long *ret,
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

	err = compel_execute_syscall(ctl, &regs, (char*)code_syscall);

	*ret = regs.gpr[3];
	return err;
}

void *remote_mmap(struct parasite_ctl *ctl,
		  void *addr, size_t length, int prot,
		  int flags, int fd, off_t offset)
{
	long map = 0;
	int err;

	err = compel_syscall(ctl, __NR_mmap, &map,
			(unsigned long)addr, length, prot, flags, fd, offset);
	if (err < 0 || (long)map < 0)
		map = 0;

	return (void *)map;
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

int arch_fetch_sas(struct parasite_ctl *ctl, struct rt_sigframe *s)
{
	long ret;
	int err;

	err = compel_syscall(ctl, __NR_sigaltstack,
			     &ret, 0, (unsigned long)&s->uc.uc_stack,
			     0, 0, 0, 0);
	return err ? err : ret;
}

/*
 * Copied for the Linux kernel arch/powerpc/include/asm/processor.h
 *
 * NOTE: 32bit tasks are not supported.
 */
#define TASK_SIZE_64TB  (0x0000400000000000UL)
#define TASK_SIZE_512TB (0x0002000000000000UL)

#define TASK_SIZE_MIN TASK_SIZE_64TB
#define TASK_SIZE_MAX TASK_SIZE_512TB

unsigned long compel_task_size(void)
{
	unsigned long task_size;

	for (task_size = TASK_SIZE_MIN; task_size < TASK_SIZE_MAX; task_size <<= 1)
		if (munmap((void *)task_size, page_size()))
			break;
	return task_size;
}
