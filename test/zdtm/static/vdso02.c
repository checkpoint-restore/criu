#include <signal.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc =
	"Restoring task with unmapped vDSO blob. Poor man's test for C/R on vdso64_enabled=0 booted kernel.\n";
const char *test_author = "Dmitry Safonov <dsafonov@virtuozzo.com>";

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2 * !!(condition)]))
#define VDSO_BAD_ADDR		(-1ul)
#define VVAR_BAD_ADDR		(-1ul)
#define BUF_SZ			1024

struct vm_area {
	unsigned long start;
	unsigned long end;
};

static int parse_vm_area(char *buf, struct vm_area *vma)
{
	if (sscanf(buf, "%lx-%lx", &vma->start, &vma->end) == 2)
		return 0;

	pr_perror("Can't find VMA bounds");
	return -1;
}

static int find_blobs(pid_t pid, struct vm_area *vdso, struct vm_area *vvar)
{
	char buf[BUF_SZ];
	int ret = -1;
	FILE *maps;

	vdso->start = VDSO_BAD_ADDR;
	vdso->end = VDSO_BAD_ADDR;
	vvar->start = VVAR_BAD_ADDR;
	vvar->end = VVAR_BAD_ADDR;

	if (snprintf(buf, BUF_SZ, "/proc/%d/maps", pid) < 0) {
		pr_perror("snprintf() failure for path");
		return -1;
	}

	maps = fopen(buf, "r");
	if (!maps) {
		pr_perror("Can't open maps for %d", pid);
		return -1;
	}

	while (fgets(buf, sizeof(buf), maps)) {
		if (strstr(buf, "[vdso]") && parse_vm_area(buf, vdso))
			goto err;

		if (strstr(buf, "[vvar]") && parse_vm_area(buf, vvar))
			goto err;
	}

	if (vdso->start != VDSO_BAD_ADDR)
		test_msg("[vdso] %lx-%lx\n", vdso->start, vdso->end);
	if (vvar->start != VVAR_BAD_ADDR)
		test_msg("[vvar] %lx-%lx\n", vvar->start, vvar->end);
	ret = 0;
err:
	fclose(maps);
	return ret;
}

#ifdef __i386__
/*
 * On i386 syscalls for speed are optimized trough vdso,
 * call raw int80 as vdso is unmapped.
 */
#define __NR32_munmap 91
#define __NR32_kill   37
#define __NR32_exit   1
struct syscall_args32 {
	uint32_t nr, arg0, arg1;
};

static inline void do_full_int80(struct syscall_args32 *args)
{
	asm volatile("int $0x80\n\t" : "+a"(args->nr), "+b"(args->arg0), "+c"(args->arg1));
}

int sys_munmap(void *addr, size_t len)
{
	struct syscall_args32 s = { 0 };

	s.nr = __NR32_munmap;
	s.arg0 = (uint32_t)(uintptr_t)addr;
	s.arg1 = (uint32_t)len;

	do_full_int80(&s);

	return (int)s.nr;
}

int sys_kill(pid_t pid, int sig)
{
	struct syscall_args32 s = { 0 };

	s.nr = __NR32_kill;
	s.arg0 = (uint32_t)pid;
	s.arg1 = (uint32_t)sig;

	do_full_int80(&s);

	return (int)s.nr;
}

void sys_exit(int status)
{
	struct syscall_args32 s = { 0 };

	s.nr = __NR32_exit;
	s.arg0 = (uint32_t)status;

	do_full_int80(&s);
}

#else /* !__i386__ */

int sys_munmap(void *addr, size_t len)
{
	return syscall(SYS_munmap, addr, len);
}

int sys_kill(pid_t pid, int sig)
{
	return syscall(SYS_kill, pid, sig);
}

void sys_exit(int status)
{
	syscall(SYS_exit, status);
}

#endif

static int unmap_blobs(void)
{
	struct vm_area vdso, vvar;
	int ret;

	if (find_blobs(getpid(), &vdso, &vvar))
		return -1;

	if (vdso.start != VDSO_BAD_ADDR) {
		ret = sys_munmap((void *)vdso.start, vdso.end - vdso.start);
		if (ret)
			return ret;
	}
	if (vvar.start != VVAR_BAD_ADDR) {
		ret = sys_munmap((void *)vvar.start, vvar.end - vvar.start);
		if (ret)
			return ret;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct vm_area vdso, vvar;
	pid_t child;
	int status, ret = -1;

	test_init(argc, argv);

	child = fork();
	if (child < 0) {
		pr_perror("fork() failed");
		exit(1);
	}

	if (child == 0) {
		child = getpid();
		if (unmap_blobs() < 0)
			syscall(SYS_exit, 1);
		sys_kill(child, SIGSTOP);
		sys_exit(2);
	}

	waitpid(child, &status, WUNTRACED);
	if (WIFEXITED(status)) {
		int ret = WEXITSTATUS(status);

		pr_err("Child unexpectedly exited with %d\n", ret);
		goto out_kill;
	} else if (WIFSIGNALED(status)) {
		int sig = WTERMSIG(status);

		pr_err("Child unexpectedly signaled with %d: %s\n", sig, strsignal(sig));
		goto out_kill;
	} else if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
		pr_err("Child is unstoppable or was stopped by other means\n");
		goto out_kill;
	}

	if (find_blobs(child, &vdso, &vvar))
		goto out_kill;
	if (vdso.start != VDSO_BAD_ADDR || vvar.start != VVAR_BAD_ADDR) {
		pr_err("Found vvar or vdso blob(s) in child, which should have unmapped them\n");
		goto out_kill;
	}

	test_daemon();
	test_waitsig();

	if (find_blobs(child, &vdso, &vvar))
		goto out_kill;
	if (vdso.start != VDSO_BAD_ADDR || vvar.start != VVAR_BAD_ADDR) {
		pr_err("Child without vdso got it after C/R\n");
		fail();
		goto out_kill;
	}

	pass();

	ret = 0;
out_kill:
	kill(child, SIGKILL);
	return ret;
}
