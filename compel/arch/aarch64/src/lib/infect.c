#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <asm/ptrace.h>
#include <linux/elf.h>

#include <compel/plugins/std/syscall-codes.h>
#include "common/page.h"
#include "uapi/compel/asm/infect-types.h"
#include "log.h"
#include "errno.h"
#include "infect.h"
#include "infect-priv.h"
#include "asm/breakpoints.h"
#include "asm/gcs-types.h"
#include <linux/prctl.h>

unsigned __page_size = 0;
unsigned __page_shift = 0;

/*
 * Injected syscall instruction
 */
const char code_syscall[] = {
	0x01, 0x00, 0x00, 0xd4, /* SVC #0 */
	0x00, 0x00, 0x20, 0xd4	/* BRK #0 */
};

static const int code_syscall_aligned = round_up(sizeof(code_syscall), sizeof(long));

static inline void __always_unused __check_code_syscall(void)
{
	BUILD_BUG_ON(code_syscall_aligned != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

static bool __compel_gcs_enabled(struct user_gcs *gcs)
{
	return gcs && (gcs->features_enabled & PR_SHADOW_STACK_ENABLE) != 0;
}

int sigreturn_prep_regs_plain(struct rt_sigframe *sigframe, user_regs_struct_t *regs, user_fpregs_struct_t *fpregs)
{
	struct fpsimd_context *fpsimd = RT_SIGFRAME_FPU(sigframe);
	struct gcs_context *gcs = RT_SIGFRAME_GCS(sigframe);

	memcpy(sigframe->uc.uc_mcontext.regs, regs->regs, sizeof(regs->regs));

	pr_debug("sigreturn_prep_regs_plain: sp %lx pc %lx\n", (long)regs->sp, (long)regs->pc);

	sigframe->uc.uc_mcontext.sp = regs->sp;
	sigframe->uc.uc_mcontext.pc = regs->pc;
	sigframe->uc.uc_mcontext.pstate = regs->pstate;

	memcpy(fpsimd->vregs, fpregs->fpstate.vregs, 32 * sizeof(__uint128_t));

	fpsimd->fpsr = fpregs->fpstate.fpsr;
	fpsimd->fpcr = fpregs->fpstate.fpcr;

	fpsimd->head.magic = FPSIMD_MAGIC;
	fpsimd->head.size = sizeof(*fpsimd);

	if (__compel_gcs_enabled(&fpregs->gcs)) {
		gcs->head.magic = GCS_MAGIC;
		gcs->head.size = sizeof(*gcs);
		gcs->reserved = 0;
		gcs->gcspr = fpregs->gcs.gcspr_el0 - 8;
		gcs->features_enabled = fpregs->gcs.features_enabled;

		pr_debug("sigframe gcspr=%llx features_enabled=%llx\n", fpregs->gcs.gcspr_el0 - 8, fpregs->gcs.features_enabled);
	} else {
		pr_debug("sigframe gcspr=[disabled]\n");
		memset(gcs, 0, sizeof(*gcs));
	}

	return 0;
}

int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe)
{
	return 0;
}

int compel_get_task_regs(pid_t pid, user_regs_struct_t *regs, user_fpregs_struct_t *ext_regs, save_regs_t save,
			 void *arg, __maybe_unused unsigned long flags)
{
	struct iovec iov;
	int ret;

	pr_info("Dumping GP/FPU registers for %d\n", pid);

	iov.iov_base = regs;
	iov.iov_len = sizeof(user_regs_struct_t);
	if ((ret = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov))) {
		pr_perror("Failed to obtain CPU registers for %d", pid);
		goto err;
	}

	iov.iov_base = &ext_regs->fpstate;
	iov.iov_len = sizeof(ext_regs->fpstate);
	if ((ret = ptrace(PTRACE_GETREGSET, pid, NT_PRFPREG, &iov))) {
		pr_perror("Failed to obtain FPU registers for %d", pid);
		goto err;
	}

	memset(&ext_regs->gcs, 0, sizeof(ext_regs->gcs));

	iov.iov_base = &ext_regs->gcs;
	iov.iov_len = sizeof(ext_regs->gcs);
	if (ptrace(PTRACE_GETREGSET, pid, NT_ARM_GCS, &iov) == 0) {
		pr_info("gcs: GCSPR_EL0 for %d: 0x%llx, features: 0x%llx\n",
			pid, ext_regs->gcs.gcspr_el0, ext_regs->gcs.features_enabled);

		if (!__compel_gcs_enabled(&ext_regs->gcs))
			pr_info("gcs: GCS is NOT enabled\n");
	} else {
		pr_info("gcs: GCS state not available for %d\n", pid);
	}

	ret = save(pid, arg, regs, ext_regs);
err:
	return ret;
}

int compel_set_task_ext_regs(pid_t pid, user_fpregs_struct_t *ext_regs)
{
	struct iovec iov;

	pr_info("Restoring GP/FPU registers for %d\n", pid);

	iov.iov_base = &ext_regs->fpstate;
	iov.iov_len = sizeof(ext_regs->fpstate);
	if (ptrace(PTRACE_SETREGSET, pid, NT_PRFPREG, &iov)) {
		pr_perror("Failed to set FPU registers for %d", pid);
		return -1;
	}
	return 0;
}

int compel_syscall(struct parasite_ctl *ctl, int nr, long *ret, unsigned long arg1, unsigned long arg2,
		   unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	user_regs_struct_t regs = ctl->orig.regs;
	int err;

	regs.regs[8] = (unsigned long)nr;
	regs.regs[0] = arg1;
	regs.regs[1] = arg2;
	regs.regs[2] = arg3;
	regs.regs[3] = arg4;
	regs.regs[4] = arg5;
	regs.regs[5] = arg6;
	regs.regs[6] = 0;
	regs.regs[7] = 0;

	err = compel_execute_syscall(ctl, &regs, code_syscall);

	*ret = regs.regs[0];
	return err;
}

void *remote_mmap(struct parasite_ctl *ctl, void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	long map;
	int err;

	err = compel_syscall(ctl, __NR_mmap, &map, (unsigned long)addr, length, prot, flags, fd, offset);
	if (err < 0 || (long)map < 0)
		map = 0;

	return (void *)map;
}

void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs)
{
	regs->pc = new_ip;
	if (stack)
		regs->sp = (unsigned long)stack;
}

bool arch_can_dump_task(struct parasite_ctl *ctl)
{
	/*
	 * TODO: Add proper check here
	 */
	return true;
}

int arch_fetch_sas(struct parasite_ctl *ctl, struct rt_sigframe *s)
{
	long ret;
	int err;

	err = compel_syscall(ctl, __NR_sigaltstack, &ret, 0, (unsigned long)&s->uc.uc_stack, 0, 0, 0, 0);
	return err ? err : ret;
}

/*
 * Range for task size calculated from the following Linux kernel files:
 *   arch/arm64/include/asm/memory.h
 *   arch/arm64/Kconfig
 *
 * TODO: handle 32 bit tasks
 */
#define TASK_SIZE_MIN (1UL << 39)
#define TASK_SIZE_MAX (1UL << 48)

unsigned long compel_task_size(void)
{
	unsigned long task_size;

	for (task_size = TASK_SIZE_MIN; task_size < TASK_SIZE_MAX; task_size <<= 1)
		if (munmap((void *)task_size, page_size()))
			break;
	return task_size;
}

static struct hwbp_cap *ptrace_get_hwbp_cap(pid_t pid)
{
	static struct hwbp_cap info;
	static int available = -1;

	if (available == -1) {
		unsigned int val;
		struct iovec iovec = {
			.iov_base = &val,
			.iov_len = sizeof(val),
		};

		if (ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_BREAK, &iovec) < 0)
			available = 0;
		else {
			info.arch = (char)((val >> 8) & 0xff);
			info.bp_count = (char)(val & 0xff);

			available = (info.arch != 0);
		}
	}

	return available == 1 ? &info : NULL;
}

int ptrace_set_breakpoint(pid_t pid, void *addr)
{
	k_rtsigset_t block;
	struct hwbp_cap *info = ptrace_get_hwbp_cap(pid);
	struct user_hwdebug_state regs = {};
	unsigned int ctrl = 0;
	struct iovec iovec;

	if (info == NULL || info->bp_count == 0)
		return 0;

	/*
	 * The struct is copied from `arch/arm64/include/asm/hw_breakpoint.h` in
	 * linux kernel:
	 *  struct arch_hw_breakpoint_ctrl {
	 *  	__u32 __reserved        : 19,
	 *  	len             : 8,
	 *  	type            : 2,
	 *  	privilege       : 2,
	 *  	enabled         : 1;
	 *  };
	 *
	 * The part of `struct arch_hw_breakpoint_ctrl` bits meaning is defined
	 * in <<ARM Architecture Reference Manual for A-profile architecture>>,
	 * D13.3.2 DBGBCR<n>_EL1, Debug Breakpoint Control Registers.
	 */
	ctrl = ARM_BREAKPOINT_LEN_4;
	ctrl = (ctrl << 2) | ARM_BREAKPOINT_EXECUTE;
	ctrl = (ctrl << 2) | AARCH64_BREAKPOINT_EL0;
	ctrl = (ctrl << 1) | ENABLE_HBP;
	regs.dbg_regs[0].addr = (__u64)addr;
	regs.dbg_regs[0].ctrl = ctrl;
	iovec.iov_base = &regs;
	iovec.iov_len = (offsetof(struct user_hwdebug_state, dbg_regs) + sizeof(regs.dbg_regs[0]));

	if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_BREAK, &iovec))
		return -1;

	/*
	 * FIXME(issues/1429): SIGTRAP can't be blocked, otherwise its handler
	 * will be reset to the default one.
	 */
	ksigfillset(&block);
	ksigdelset(&block, SIGTRAP);
	if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(k_rtsigset_t), &block)) {
		pr_perror("Can't block signals for %d", pid);
		return -1;
	}

	if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
		pr_perror("Unable to restart the  stopped tracee process %d", pid);
		return -1;
	}

	return 1;
}

int ptrace_flush_breakpoints(pid_t pid)
{
	struct hwbp_cap *info = ptrace_get_hwbp_cap(pid);
	struct user_hwdebug_state regs = {};
	unsigned int ctrl = 0;
	struct iovec iovec;

	if (info == NULL || info->bp_count == 0)
		return 0;

	ctrl = ARM_BREAKPOINT_LEN_4;
	ctrl = (ctrl << 2) | ARM_BREAKPOINT_EXECUTE;
	ctrl = (ctrl << 2) | AARCH64_BREAKPOINT_EL0;
	ctrl = (ctrl << 1) | DISABLE_HBP;
	regs.dbg_regs[0].addr = 0ul;
	regs.dbg_regs[0].ctrl = ctrl;

	iovec.iov_base = &regs;
	iovec.iov_len = (offsetof(struct user_hwdebug_state, dbg_regs) + sizeof(regs.dbg_regs[0]));

	if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_BREAK, &iovec))
		return -1;

	return 0;
}

int inject_gcs_cap_token(struct parasite_ctl *ctl, pid_t pid, struct user_gcs *gcs)
{
	struct iovec gcs_iov = { .iov_base = gcs, .iov_len = sizeof(*gcs) };

	uint64_t token_addr = gcs->gcspr_el0 - 8;
	uint64_t sigtramp_addr = gcs->gcspr_el0 - 16;

	uint64_t cap_token = ALIGN_DOWN(GCS_SIGNAL_CAP(token_addr), 8);
	unsigned long restorer_addr;

	pr_info("gcs: (setup) CAP token: 0x%lx at addr: 0x%lx\n", cap_token, token_addr);

	/* Inject capability token at gcspr_el0 - 8 */
	if (ptrace(PTRACE_POKEDATA, pid, (void *)token_addr, cap_token)) {
		pr_perror("gcs: (setup) Inject GCS cap token failed");
		return -1;
	}

	/* Inject restorer trampoline address (gcspr_el0 - 16) */
	restorer_addr = ctl->parasite_ip;
	if (ptrace(PTRACE_POKEDATA, pid, (void *)sigtramp_addr, restorer_addr)) {
		pr_perror("gcs: (setup) Inject GCS restorer failed");
		return -1;
	}

	/* Update GCSPR_EL0 */
	gcs->gcspr_el0 = token_addr;
	if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_GCS, &gcs_iov)) {
		pr_perror("gcs: PTRACE_SETREGS FAILED");
		return -1;
	}

	pr_debug("gcs: parasite_ip=%#lx sp=%#llx gcspr_el0=%#llx\n",
		 ctl->parasite_ip, ctl->orig.regs.sp, gcs->gcspr_el0);

	return 0;
}

int parasite_setup_shstk(struct parasite_ctl *ctl, user_fpregs_struct_t *ext_regs)
{
	struct user_gcs gcs;
	struct iovec gcs_iov = { .iov_base = &gcs, .iov_len = sizeof(gcs) };
	pid_t pid = ctl->rpid;

	if (ptrace(PTRACE_GETREGSET, pid, NT_ARM_GCS, &gcs_iov) != 0) {
		pr_perror("GCS state not available for %d", pid);
		return -1;
	}

	if (!__compel_gcs_enabled(&gcs))
		return 0;

	if (inject_gcs_cap_token(ctl, pid, &gcs)) {
		pr_perror("Failed to inject GCS cap token for %d", pid);
		return -1;
	}

	pr_info("gcs: GCS enabled for %d\n", pid);

	return 0;
}
