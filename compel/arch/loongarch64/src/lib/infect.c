#include <sys/types.h>
#include <sys/uio.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <errno.h>

#include <compel/asm/fpu.h>
#include <compel/cpu.h>
#include "errno.h"
#include <compel/plugins/std/syscall-codes.h>
#include <compel/plugins/std/syscall.h>
#include "common/err.h"
#include "common/page.h"
#include "asm/infect-types.h"
#include "ptrace.h"
#include "infect.h"
#include "infect-priv.h"
#include "log.h"
#include "common/bug.h"

/*
 * Injected syscall instruction
 * loongarch64 is Little Endian
 */
const char code_syscall[] = {
	0x00, 0x00, 0x2b, 0x00, /* syscall    */
	0x00, 0x00, 0x2a, 0x00	/*  break      */
};

int sigreturn_prep_regs_plain(struct rt_sigframe *sigframe, user_regs_struct_t *regs, user_fpregs_struct_t *fpregs)
{
	sigcontext_t *sc;
	fpu_context_t *fpu;

	sc = RT_SIGFRAME_SIGCTX(sigframe);
	memcpy(sc->regs, regs->regs, sizeof(regs->regs));
	sc->pc = regs->pc;

	fpu = RT_SIGFRAME_FPU(sigframe);
	memcpy(fpu->regs, fpregs->regs, sizeof(fpregs->regs));
	fpu->fcc = fpregs->fcc;
	fpu->fcsr = fpregs->fcsr;
	return 0;
}

int sigreturn_prep_fpu_frame_plain(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe)
{
	return 0;
}

int compel_get_task_regs(pid_t pid, user_regs_struct_t *regs, user_fpregs_struct_t *ext_regs, save_regs_t save,
			 void *arg, __maybe_unused unsigned long flags)
{
	user_fpregs_struct_t tmp, *fpregs = ext_regs ? ext_regs : &tmp;
	struct iovec iov;
	int ret;

	pr_info("Dumping GP/FPU registers for %d\n", pid);

	iov.iov_base = regs;
	iov.iov_len = sizeof(user_regs_struct_t);
	if ((ret = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov))) {
		pr_perror("Failed to obtain CPU registers for %d", pid);
		goto err;
	}

	/*
	 * Refer to Linux kernel arch/loongarch/kernel/signal.c
	 */
	if (regs->regs[0]) {
		switch (regs->regs[4]) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			regs->regs[4] = regs->orig_a0;
			regs->pc -= 4;
			break;
		case -ERESTART_RESTARTBLOCK:
			regs->regs[4] = regs->orig_a0;
			regs->regs[11] = __NR_restart_syscall;
			regs->pc -= 4;
			break;
		}
		regs->regs[0] = 0; /* Don't deal with this again.  */
	}

	iov.iov_base = fpregs;
	iov.iov_len = sizeof(user_fpregs_struct_t);
	if ((ret = ptrace(PTRACE_GETREGSET, pid, NT_PRFPREG, &iov))) {
		pr_perror("Failed to obtain FPU registers for %d", pid);
		goto err;
	}

	ret = save(arg, regs, fpregs);
err:
	return 0;
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

/*
 * Registers $4 ~ $11 represents arguments a0 ~ a7, especially a7 is
 * used as syscall number.
 */
int compel_syscall(struct parasite_ctl *ctl, int nr, long *ret, unsigned long arg1, unsigned long arg2,
		   unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	int err;
	user_regs_struct_t regs = ctl->orig.regs;

	regs.regs[11] = (unsigned long)nr;
	regs.regs[4] = arg1;
	regs.regs[5] = arg2;
	regs.regs[6] = arg3;
	regs.regs[7] = arg4;
	regs.regs[8] = arg5;
	regs.regs[9] = arg6;
	err = compel_execute_syscall(ctl, &regs, code_syscall);

	*ret = regs.regs[4];

	return err;
}

void *remote_mmap(struct parasite_ctl *ctl, void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	long map;
	int err;

	err = compel_syscall(ctl, __NR_mmap, &map, (unsigned long)addr, length, prot, flags, fd, offset >> PAGE_SHIFT);

	if (err < 0 || IS_ERR_VALUE(map)) {
		pr_err("remote mmap() failed: %s\n", strerror(-map));
		return NULL;
	}

	return (void *)map;
}

/*
 * regs must be inited when calling this function from original context
 */
void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs)
{
	regs->pc = new_ip;
	if (stack)
		regs->regs[4] = (unsigned long)stack;
}

bool arch_can_dump_task(struct parasite_ctl *ctl)
{
	return true;
}

int arch_fetch_sas(struct parasite_ctl *ctl, struct rt_sigframe *s)
{
	long ret;
	int err;

	err = compel_syscall(ctl, __NR_sigaltstack, &ret, 0, (unsigned long)&s->rs_uc.uc_stack, 0, 0, 0, 0);
	return err ? err : ret;
}

/*
 * TODO: add feature
 */
int ptrace_set_breakpoint(pid_t pid, void *addr)
{
	return 0;
}

int ptrace_flush_breakpoints(pid_t pid)
{
	return 0;
}

/*
 * Refer to Linux kernel arch/loongarch/include/asm/processor.h
 */
#define TASK_SIZE32	(1UL) << 31
#define TASK_SIZE64_MIN (1UL) << 40
#define TASK_SIZE64_MAX (1UL) << 48

unsigned long compel_task_size(void)
{
	unsigned long task_size;
	for (task_size = TASK_SIZE64_MIN; task_size < TASK_SIZE64_MAX; task_size <<= 1)
		if (munmap((void *)task_size, page_size()))
			break;
	return task_size;
}
