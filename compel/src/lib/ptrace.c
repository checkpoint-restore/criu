#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <signal.h>
#include <elf.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "common/compiler.h"

#include "uapi/compel/asm/infect-types.h"
#include "ptrace.h"

#include "log.h"

int ptrace_suspend_seccomp(pid_t pid)
{
	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD) < 0) {
		pr_perror("suspending seccomp failed");
		return -1;
	}

	return 0;
}

int ptrace_peek_area(pid_t pid, void *dst, void *addr, long bytes)
{
	unsigned long w;
	int old_errno = errno;

	if (bytes & (sizeof(long) - 1)) {
		pr_err("Peek request with non-word size %ld\n", bytes);
		return -1;
	}

	errno = 0;
	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *d = dst, *a = addr;

		d[w] = ptrace(PTRACE_PEEKDATA, pid, a + w, NULL);
		if (d[w] == -1U && errno) {
			pr_perror("PEEKDATA failed");
			goto err;
		}
	}
	errno = old_errno;
	return 0;
err:
	return -errno;
}

int ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes)
{
	unsigned long w;

	if (bytes & (sizeof(long) - 1)) {
		pr_err("Poke request with non-word size %ld\n", bytes);
		return -1;
	}

	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *s = src, *a = addr;

		if (ptrace(PTRACE_POKEDATA, pid, a + w, s[w])) {
			pr_perror("POKEDATA failed");
			goto err;
		}
	}
	return 0;
err:
	return -errno;
}

/* don't swap big space, it might overflow the stack */
int ptrace_swap_area(pid_t pid, void *dst, void *src, long bytes)
{
	void *t = alloca(bytes);
	int err;

	err = ptrace_peek_area(pid, t, dst, bytes);
	if (err)
		return err;

	err = ptrace_poke_area(pid, src, dst, bytes);
	if (err) {
		int err2;

		pr_err("Can't poke %d @ %p from %p sized %ld\n", pid, dst, src, bytes);

		err2 = ptrace_poke_area(pid, t, dst, bytes);
		if (err2) {
			pr_err("Can't restore the original data with poke\n");
			return err2;
		}
		return err;
	}

	memcpy(src, t, bytes);

	return 0;
}

int __attribute__((weak)) ptrace_get_regs(int pid, user_regs_struct_t *regs)
{
	struct iovec iov;

	iov.iov_base = regs;
	iov.iov_len = sizeof(user_regs_struct_t);
	return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
}

int __attribute__((weak)) ptrace_set_regs(int pid, user_regs_struct_t *regs)
{
	struct iovec iov;

	iov.iov_base = regs;
	iov.iov_len = sizeof(user_regs_struct_t);
	return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}
