#include <sys/ptrace.h>
#include <sys/types.h>
#include "asm/parasite-syscall.h"
#include "uapi/std/syscall-codes.h"
#include "asm/types.h"
#include "criu-log.h"
#include "kerndat.h"
#include "parasite-syscall.h"
#include "errno.h"
#include "infect.h"
#include "infect-priv.h"

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

