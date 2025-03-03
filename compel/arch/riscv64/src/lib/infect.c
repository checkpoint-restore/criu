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

unsigned __page_size = 0;
unsigned __page_shift = 0;

/*
 * Injected syscall instruction
 */
const char code_syscall[] = {
	0x73, 0x00, 0x00, 0x00, /* ecall */
	0x73, 0x00, 0x10, 0x00	/* ebreak */
};

static const int code_syscall_aligned = round_up(sizeof(code_syscall), sizeof(long));

static inline void __always_unused __check_code_syscall(void)
{
	BUILD_BUG_ON(code_syscall_aligned != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

int sigreturn_prep_regs_plain(struct rt_sigframe *sigframe, user_regs_struct_t *regs, user_fpregs_struct_t *fpregs)
{
	sigframe->uc.uc_mcontext.__gregs[0] = regs->pc;
	sigframe->uc.uc_mcontext.__gregs[1] = regs->ra;
	sigframe->uc.uc_mcontext.__gregs[2] = regs->sp;
	sigframe->uc.uc_mcontext.__gregs[3] = regs->gp;
	sigframe->uc.uc_mcontext.__gregs[4] = regs->tp;
	sigframe->uc.uc_mcontext.__gregs[5] = regs->t0;
	sigframe->uc.uc_mcontext.__gregs[6] = regs->t1;
	sigframe->uc.uc_mcontext.__gregs[7] = regs->t2;
	sigframe->uc.uc_mcontext.__gregs[8] = regs->s0;
	sigframe->uc.uc_mcontext.__gregs[9] = regs->s1;
	sigframe->uc.uc_mcontext.__gregs[10] = regs->a0;
	sigframe->uc.uc_mcontext.__gregs[11] = regs->a1;
	sigframe->uc.uc_mcontext.__gregs[12] = regs->a2;
	sigframe->uc.uc_mcontext.__gregs[13] = regs->a3;
	sigframe->uc.uc_mcontext.__gregs[14] = regs->a4;
	sigframe->uc.uc_mcontext.__gregs[15] = regs->a5;
	sigframe->uc.uc_mcontext.__gregs[16] = regs->a6;
	sigframe->uc.uc_mcontext.__gregs[17] = regs->a7;
	sigframe->uc.uc_mcontext.__gregs[18] = regs->s2;
	sigframe->uc.uc_mcontext.__gregs[19] = regs->s3;
	sigframe->uc.uc_mcontext.__gregs[20] = regs->s4;
	sigframe->uc.uc_mcontext.__gregs[21] = regs->s5;
	sigframe->uc.uc_mcontext.__gregs[22] = regs->s6;
	sigframe->uc.uc_mcontext.__gregs[23] = regs->s7;
	sigframe->uc.uc_mcontext.__gregs[24] = regs->s8;
	sigframe->uc.uc_mcontext.__gregs[25] = regs->s9;
	sigframe->uc.uc_mcontext.__gregs[26] = regs->s10;
	sigframe->uc.uc_mcontext.__gregs[27] = regs->s11;
	sigframe->uc.uc_mcontext.__gregs[28] = regs->t3;
	sigframe->uc.uc_mcontext.__gregs[29] = regs->t4;
	sigframe->uc.uc_mcontext.__gregs[30] = regs->t5;
	sigframe->uc.uc_mcontext.__gregs[31] = regs->t6;

	memcpy(sigframe->uc.uc_mcontext.__fpregs.__d.__f, fpregs->f, sizeof(fpregs->f));
	sigframe->uc.uc_mcontext.__fpregs.__d.__fcsr = fpregs->fcsr;

	return 0;
}

int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe)
{
	return 0;
}

int compel_get_task_regs(pid_t pid, user_regs_struct_t *regs, user_fpregs_struct_t *ext_regs, save_regs_t save,
			 void *arg, __maybe_unused unsigned long flags)
{
	user_fpregs_struct_t tmp, *fpsimd = ext_regs ? ext_regs : &tmp;
	struct iovec iov;
	int ret = -1;

	pr_info("Dumping FPU registers for %d\n", pid);

	iov.iov_base = fpsimd;
	iov.iov_len = sizeof(*fpsimd);
	if ((ret = ptrace(PTRACE_GETREGSET, pid, NT_PRFPREG, &iov))) {
		pr_perror("Failed to obtain FPU registers for %d", pid);
		return -1;
	}

	ret = save(pid, arg, regs, fpsimd);
	return ret;
}

int compel_set_task_ext_regs(pid_t pid, user_fpregs_struct_t *ext_regs)
{
	struct iovec iov;

	pr_info("Restoring GP/FPU registers for %d\n", pid);

	iov.iov_base = ext_regs;
	iov.iov_len = sizeof(*ext_regs);
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

	regs.a7 = (unsigned long)nr;
	regs.a0 = arg1;
	regs.a1 = arg2;
	regs.a2 = arg3;
	regs.a3 = arg4;
	regs.a4 = arg5;
	regs.a5 = arg6;
	regs.a6 = 0;

	err = compel_execute_syscall(ctl, &regs, code_syscall);

	*ret = regs.a0;
	return err;
}

/*
 * Calling the mmap system call in the context of the target (victim) process using the compel_syscall function.
 * Used during the infection process to allocate memory for the parasite code.
*/
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
	 * TODO: Add proper check here.
	 */
	return true;
}

/*
 * Fetch the signal alternate stack (sigaltstack),
 * sas is a separate memory area for the signal handler to run on,
 * avoiding potential issues with the main process stack
*/
int arch_fetch_sas(struct parasite_ctl *ctl, struct rt_sigframe *s)
{
	long ret;
	int err;

	err = compel_syscall(ctl, __NR_sigaltstack, &ret, 0, (unsigned long)&s->uc.uc_stack, 0, 0, 0, 0);
	return err ? err : ret;
}

/*
 * Task size is the maximum virtual address space size that a process can occupy in the memory
 * Refer to linux kernel arch/riscv/include/asm/pgtable.h,
 * task size is:
 * -        0x9fc00000	(~2.5GB) for RV32.
 * -      0x4000000000	( 256GB) for RV64 using SV39 mmu
 * -    0x800000000000	( 128TB) for RV64 using SV48 mmu
 * - 0x100000000000000	(  64PB) for RV64 using SV57 mmu
 */
#define TASK_SIZE_MIN (1UL << 38)
#define TASK_SIZE_MAX (1UL << 56)

unsigned long compel_task_size(void)
{
	unsigned long task_size;

	for (task_size = TASK_SIZE_MIN; task_size < TASK_SIZE_MAX; task_size <<= 1)
		if (munmap((void *)task_size, page_size()))
			break;
	return task_size;
}

/*
 * Get task registers (overwrites weak function)
 */
int ptrace_get_regs(int pid, user_regs_struct_t *regs)
{
	struct iovec iov;

	iov.iov_base = regs;
	iov.iov_len = sizeof(user_regs_struct_t);
	return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
}

/*
 * Set task registers (overwrites weak function)
 */
int ptrace_set_regs(int pid, user_regs_struct_t *regs)
{
	struct iovec iov;

	iov.iov_base = regs;
	iov.iov_len = sizeof(user_regs_struct_t);
	return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}
