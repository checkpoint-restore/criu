#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include "asm/parasite-syscall.h"
#include "uapi/std/syscall-codes.h"
#include "asm/types.h"
#include "criu-log.h"
#include "kerndat.h"
#include "parasite-syscall.h"
#include "errno.h"
#include "infect.h"
#include "infect-priv.h"

int compel_get_task_regs(pid_t pid, user_regs_struct_t regs, save_regs_t save, void *arg)
{
	struct iovec iov;
	user_fpregs_struct_t fpsimd;
	int ret;

	pr_info("Dumping GP/FPU registers for %d\n", pid);

	iov.iov_base = &regs;
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

	ret = save(arg, &regs, &fpsimd);
err:
	return ret;
}

