#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include <compel/plugins/std/syscall-codes.h>
#include "common/page.h"
#include "uapi/compel/asm/infect-types.h"
#include "log.h"
#include "errno.h"
#include "infect.h"
#include "infect-priv.h"

/*
 * Injected syscall instruction
 */
const char code_syscall[] = {
	0x01, 0x00, 0x00, 0xd4,		/* SVC #0 */
	0x00, 0x00, 0x20, 0xd4		/* BRK #0 */
};

static const int
code_syscall_aligned = round_up(sizeof(code_syscall), sizeof(long));

static inline void __always_unused __check_code_syscall(void)
{
	BUILD_BUG_ON(code_syscall_aligned != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

int sigreturn_prep_regs_plain(struct rt_sigframe *sigframe,
			      user_regs_struct_t *regs,
			      user_fpregs_struct_t *fpregs)
{
	struct fpsimd_context *fpsimd = RT_SIGFRAME_FPU(sigframe);

	memcpy(sigframe->uc.uc_mcontext.regs, regs->regs, sizeof(regs->regs));

	sigframe->uc.uc_mcontext.sp	= regs->sp;
	sigframe->uc.uc_mcontext.pc	= regs->pc;
	sigframe->uc.uc_mcontext.pstate	= regs->pstate;

	memcpy(fpsimd->vregs, fpregs->vregs, 32 * sizeof(__uint128_t));

	fpsimd->fpsr = fpregs->fpsr;
	fpsimd->fpcr = fpregs->fpcr;

	fpsimd->head.magic = FPSIMD_MAGIC;
	fpsimd->head.size = sizeof(*fpsimd);

	return 0;
}

int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *sigframe,
				   struct rt_sigframe *rsigframe)
{
	return 0;
}

int get_task_regs(pid_t pid, user_regs_struct_t *regs, save_regs_t save,
		  void *arg, __maybe_unused unsigned long flags)
{
	struct iovec iov;
	user_fpregs_struct_t fpsimd;
	int ret;

	pr_info("Dumping GP/FPU registers for %d\n", pid);

	iov.iov_base = regs;
	iov.iov_len = sizeof(user_regs_struct_t);
	if ((ret = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov))) {
		pr_perror("Failed to obtain CPU registers for %d", pid);
		goto err;
	}

	iov.iov_base = &fpsimd;
	iov.iov_len = sizeof(fpsimd);
	if ((ret = ptrace(PTRACE_GETREGSET, pid, NT_PRFPREG, &iov))) {
		pr_perror("Failed to obtain FPU registers for %d", pid);
		goto err;
	}

	ret = save(arg, regs, &fpsimd);
err:
	return ret;
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

void *remote_mmap(struct parasite_ctl *ctl,
		void *addr, size_t length, int prot,
		int flags, int fd, off_t offset)
{
	long map;
	int err;

	err = compel_syscall(ctl, __NR_mmap, &map,
			(unsigned long)addr, length, prot, flags, fd, offset);
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

	err = compel_syscall(ctl, __NR_sigaltstack,
			     &ret, 0, (unsigned long)&s->uc.uc_stack,
			     0, 0, 0, 0);
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

