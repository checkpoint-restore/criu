#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/auxv.h>
#include "asm/fpu.h"
#include "asm/types.h"
#include "errno.h"
#include "asm/cpu.h"
#include "parasite-syscall.h"
#include "infect.h"
#include "infect-priv.h"

#define get_signed_user_reg(pregs, name)				\
	((user_regs_native(pregs)) ? (int64_t)((pregs)->native.name) :	\
				(int32_t)((pregs)->compat.name))

int compel_get_task_regs(pid_t pid, user_regs_struct_t regs, save_regs_t save, void *arg)
{
	user_fpregs_struct_t xsave	= {  }, *xs = NULL;

	struct iovec iov;
	int ret = -1;

	pr_info("Dumping general registers for %d in %s mode\n", pid,
			user_regs_native(&regs) ? "native" : "compat");

	/* Did we come from a system call? */
	if (get_signed_user_reg(&regs, orig_ax) >= 0) {
		/* Restart the system call */
		switch (get_signed_user_reg(&regs, ax)) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			set_user_reg(&regs, ax, get_user_reg(&regs, orig_ax));
			set_user_reg(&regs, ip, get_user_reg(&regs, ip) - 2);
			break;
		case -ERESTART_RESTARTBLOCK:
			pr_warn("Will restore %d with interrupted system call\n", pid);
			set_user_reg(&regs, ax, -EINTR);
			break;
		}
	}

#ifndef PTRACE_GETREGSET
# define PTRACE_GETREGSET 0x4204
#endif

	if (!cpu_has_feature(X86_FEATURE_FPU))
		goto out;

	/*
	 * FPU fetched either via fxsave or via xsave,
	 * thus decode it accrodingly.
	 */

	pr_info("Dumping GP/FPU registers for %d\n", pid);

	if (cpu_has_feature(X86_FEATURE_OSXSAVE)) {
		iov.iov_base = &xsave;
		iov.iov_len = sizeof(xsave);

		if (ptrace(PTRACE_GETREGSET, pid, (unsigned int)NT_X86_XSTATE, &iov) < 0) {
			pr_perror("Can't obtain FPU registers for %d", pid);
			goto err;
		}
	} else {
		if (ptrace(PTRACE_GETFPREGS, pid, NULL, &xsave)) {
			pr_perror("Can't obtain FPU registers for %d", pid);
			goto err;
		}
	}

	xs = &xsave;
out:
	ret = save(arg, &regs, xs);
err:
	return ret;
}
