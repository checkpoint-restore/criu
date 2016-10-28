#include <sys/ptrace.h>
#include <sys/types.h>
#include "asm/parasite-syscall.h"
#include <compel/plugins/std/syscall-codes.h>
#include <compel/asm/processor-flags.h>
#include "asm/types.h"
#include "criu-log.h"
#include "kerndat.h"
#include "parasite-syscall.h"
#include "compel/include/errno.h"
#include "infect.h"
#include "infect-priv.h"

/*
 * Injected syscall instruction
 */
const char code_syscall[] = {
	0x00, 0x00, 0x00, 0xef,         /* SVC #0  */
	0xf0, 0x01, 0xf0, 0xe7          /* UDF #32 */
};

static const int
code_syscall_aligned = round_up(sizeof(code_syscall), sizeof(long));

static inline __always_unused void __check_code_syscall(void)
{
	BUILD_BUG_ON(code_syscall_aligned != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

#define PTRACE_GETVFPREGS 27
int compel_get_task_regs(pid_t pid, user_regs_struct_t regs, save_regs_t save, void *arg)
{
	user_fpregs_struct_t vfp;
	int ret = -1;

	pr_info("Dumping GP/FPU registers for %d\n", pid);

	if (ptrace(PTRACE_GETVFPREGS, pid, NULL, &vfp)) {
		pr_perror("Can't obtain FPU registers for %d", pid);
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

	ret = save(arg, &regs, &vfp);
err:
	return ret;
}

int compel_syscall(struct parasite_ctl *ctl, int nr, unsigned long *ret,
		unsigned long arg1,
		unsigned long arg2,
		unsigned long arg3,
		unsigned long arg4,
		unsigned long arg5,
		unsigned long arg6)
{
	user_regs_struct_t regs = ctl->orig.regs;
	int err;

	regs.ARM_r7 = (unsigned long)nr;
	regs.ARM_r0 = arg1;
	regs.ARM_r1 = arg2;
	regs.ARM_r2 = arg3;
	regs.ARM_r3 = arg4;
	regs.ARM_r4 = arg5;
	regs.ARM_r5 = arg6;

	err = compel_execute_syscall(ctl, &regs, code_syscall);

	*ret = regs.ARM_r0;
	return err;
}

void *remote_mmap(struct parasite_ctl *ctl,
		  void *addr, size_t length, int prot,
		  int flags, int fd, off_t offset)
{
	unsigned long map;
	int err;

	if (offset & ~PAGE_MASK)
		return 0;

	err = compel_syscall(ctl, __NR_mmap2, &map,
			(unsigned long)addr, length, prot, flags, fd, offset >> 12);
	if (err < 0 || map > kdat.task_size)
		map = 0;

	return (void *)map;
}

void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs)
{
	regs->ARM_pc = new_ip;
	if (stack)
		regs->ARM_sp = (unsigned long)stack;

	/* Make sure flags are in known state */
	regs->ARM_cpsr &= PSR_f | PSR_s | PSR_x | MODE32_BIT;
}

bool arch_can_dump_task(struct parasite_ctl *ctl)
{
	/*
	 * TODO: Add proper check here
	 */
	return true;
}
