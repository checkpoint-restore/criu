#include <string.h>
#include <unistd.h>

#include "asm/types.h"
#include "compiler.h"
#include "ptrace.h"
#include "asm/processor-flags.h"
#include "protobuf.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/creds.pb-c.h"
#include "parasite-syscall.h"
#include "syscall.h"
#include "log.h"
#include "util.h"
#include "cpu.h"
#include "elf.h"
#include "parasite-syscall.h"
#include "restorer.h"


/*
 * Injected syscall instruction
 */
const char code_syscall[] = {
	0x00, 0x00, 0x00, 0xef,         /* SVC #0  */
	0xf0, 0x01, 0xf0, 0xe7          /* UDF #32 */
};

const int code_syscall_size = round_up(sizeof(code_syscall), sizeof(long));

static inline void __check_code_syscall(void)
{
	BUILD_BUG_ON(sizeof(code_syscall) != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}


void parasite_setup_regs(unsigned long new_ip, user_regs_struct_t *regs)
{
	regs->ARM_pc = new_ip;

	/* Avoid end of syscall processing */
	regs->ARM_ORIG_r0 = -1;

	/* Make sure flags are in known state */
	regs->ARM_cpsr &= PSR_f | PSR_s | PSR_x | MODE32_BIT;
}

bool arch_can_dump_task(pid_t pid)
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
	user_regs_struct_t regs = ctl->regs_orig;
	int err;

	regs.ARM_r7 = (unsigned long)nr;
	regs.ARM_r0 = arg1;
	regs.ARM_r1 = arg2;
	regs.ARM_r2 = arg3;
	regs.ARM_r3 = arg4;
	regs.ARM_r4 = arg5;
	regs.ARM_r5 = arg6;

	parasite_setup_regs(ctl->syscall_ip, &regs);
	err = __parasite_execute(ctl, ctl->pid.real, &regs);
	if (err)
		return err;

	*ret = regs.ARM_r0;
	return 0;
}

#define assign_reg(dst, src, e)		dst->e = (__typeof__(dst->e))src.ARM_##e

#define PTRACE_GETVFPREGS 27
int get_task_regs(pid_t pid, CoreEntry *core, const struct parasite_ctl *ctl)
{
	user_regs_struct_t regs = {{-1}};
	struct user_vfp vfp;
	int ret = -1;

	pr_info("Dumping GP/FPU registers for %d\n", pid);

	if (ctl)
		regs = ctl->regs_orig;
	else {
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs)) {
			pr_err("Can't obtain GP registers for %d\n", pid);
			goto err;
		}
	}

	if (ptrace(PTRACE_GETVFPREGS, pid, NULL, &vfp)) {
		pr_err("Can't obtain FPU registers for %d\n", pid);
		goto err;
	}

	/* Did we come from a system call? */
	if ((int)regs.ARM_ORIG_r0 >= 0) {
		/* Restart the system call */
		switch ((long)(int)regs.ARM_r0) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			regs.ARM_r0 = regs.ARM_ORIG_r0;
			regs.ARM_pc -= 4;
			break;
		case -ERESTART_RESTARTBLOCK:
			regs.ARM_r0 = __NR_restart_syscall;
			regs.ARM_pc -= 4;
			break;
		}
	}


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
	core->ti_arm->gpregs->orig_r0 = regs.ARM_ORIG_r0;


	// Save the VFP state

	memcpy(CORE_THREAD_ARCH_INFO(core)->fpstate->vfp_regs, &vfp.fpregs, sizeof(vfp.fpregs));
	CORE_THREAD_ARCH_INFO(core)->fpstate->fpscr = vfp.fpscr;

	ret = 0;

err:
	return ret;
}

int arch_alloc_thread_info(CoreEntry *core)
{
	ThreadInfoArm *ti_arm;
	UserArmRegsEntry *gpregs;
	UserArmVfpstateEntry *fpstate;
	ThreadCoreEntry *thread_core;

	ti_arm = xmalloc(sizeof(*ti_arm));
	if (!ti_arm)
		goto err;
	thread_info_arm__init(ti_arm);

	gpregs = xmalloc(sizeof(*gpregs));
	user_arm_regs_entry__init(gpregs);
	ti_arm->gpregs = gpregs;

	fpstate = xmalloc(sizeof(*fpstate));
	user_arm_vfpstate_entry__init(fpstate);
	fpstate->vfp_regs = xmalloc(32*sizeof(unsigned long long));
	fpstate->n_vfp_regs = 32;
	ti_arm->fpstate = fpstate;

	core->ti_arm = ti_arm;


	thread_core = xmalloc(sizeof(*thread_core));
	if (!thread_core)
		goto err;
	thread_core_entry__init(thread_core);
	core->thread_core = thread_core;

err:
	return 0;
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

int sigreturn_prep_fpu_frame(struct thread_restore_args *args, CoreEntry *core)
{
	memcpy(args->fpu_state.ufp.fpregs, CORE_THREAD_ARCH_INFO(core)->fpstate->vfp_regs,
		sizeof(args->fpu_state.ufp.fpregs));
	args->fpu_state.ufp.fpscr = CORE_THREAD_ARCH_INFO(core)->fpstate->fpscr;

	return 0;
}

void *mmap_seized(struct parasite_ctl *ctl,
		  void *addr, size_t length, int prot,
		  int flags, int fd, off_t offset)
{
	unsigned long map;
	int err;

	if (offset & ~PAGE_MASK)
		return 0;

	err = syscall_seized(ctl, __NR_mmap2, &map,
			(unsigned long)addr, length, prot, flags, fd, offset >> 12);
	if (err < 0 || map > TASK_SIZE)
		map = 0;

	return (void *)map;
}
