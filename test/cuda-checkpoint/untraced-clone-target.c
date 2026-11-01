/* Target process used by backend-errors.py to test CLONE_UNTRACED detection. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int write_marker(const char *path, int value)
{
	FILE *file = fopen(path, "w");

	if (!file)
		return -1;
	if (fprintf(file, "%d\n", value) < 0) {
		fclose(file);
		return -1;
	}
	return fclose(file);
}

#ifdef __x86_64__
static int spawn_untraced(unsigned long flags, void *stack_top)
{
	register long r10 __asm__("r10") = 0;
	register long r8 __asm__("r8") = 0;
	long ret;

	/*
	 * Invoke SYS_clone directly because musl's clone() wrapper rejects
	 * CLONE_THREAD with EINVAL, and a raw CLONE_THREAD task without its
	 * own TLS must not call into libc.
	 */
	__asm__ volatile(
		"syscall\n\t"
		"testq %%rax, %%rax\n\t"
		"jnz 1f\n\t"
		"0:\n\t"
		"movl %[nr_pause], %%eax\n\t"
		"syscall\n\t"
		"jmp 0b\n\t"
		"1:\n\t"
		: "=a"(ret)
		: "0"((long)SYS_clone), "D"(flags), "S"(stack_top),
		  "d"(0L), "r"(r10), "r"(r8),
		  [nr_pause] "i"(SYS_pause)
		: "rcx", "r11", "cc", "memory");

	return ret < 0 ? -1 : (int)ret;
}
#else
static int cloned_task(void *arg)
{
	(void)arg;
	for (;;)
		pause();
	return 0;
}

static int spawn_untraced(unsigned long flags, void *stack_top)
{
	return clone(cloned_task, stack_top, (int)flags, NULL);
}
#endif

int main(int argc, char **argv)
{
	static char stack[65536] __attribute__((aligned(16)));
	const struct timespec delay = { .tv_nsec = 1000000 };
	unsigned long flags = CLONE_UNTRACED | SIGCHLD;
	int pid;

	if (argc != 5)
		return 1;
	if (!strcmp(argv[1], "thread"))
		flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
			CLONE_THREAD | CLONE_UNTRACED;

	if (write_marker(argv[2], (int)getpid()))
		return 1;

	while (access(argv[3], F_OK) != 0)
		nanosleep(&delay, NULL);

	pid = spawn_untraced(flags, stack + sizeof(stack));
	if (pid <= 0)
		return 1;

	if (write_marker(argv[4], pid))
		return 1;

	for (;;)
		pause();
}
