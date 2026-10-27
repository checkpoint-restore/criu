#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Detect a task created while the CUDA restore thread runs";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

static char *filename;
TEST_OPTION(filename, string, "file used to synchronize task creation", 1);

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

int main(int argc, char **argv)
{
	static char stack[65536] __attribute__((aligned(16)));
	const struct timespec delay = { .tv_nsec = 1000000 };
	unsigned long flags = CLONE_UNTRACED | SIGCHLD;
	char trigger[PATH_MAX], marker[PATH_MAX];
	FILE *file;
	int pid;

	test_init(argc, argv);
#ifdef CUDA_MOCK_THREAD
	flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_UNTRACED;
#endif
	snprintf(trigger, sizeof(trigger), "%s.trigger", filename);
	snprintf(marker, sizeof(marker), "%s.clone", filename);
	test_daemon();

	while (access(trigger, F_OK)) {
		if (!test_go()) {
			fail("task creation was not triggered");
			return 1;
		}
		nanosleep(&delay, NULL);
	}
	pid = spawn_untraced(flags, stack + sizeof(stack));
	if (pid <= 0) {
		fail("Unable to create an untraced task");
		return 1;
	}
	file = fopen(marker, "w");
	if (!file || fprintf(file, "%d\n", pid) < 0 || fclose(file)) {
		fail("Unable to write task creation marker");
		return 1;
	}

	test_waitsig();
#ifndef CUDA_MOCK_THREAD
	if (kill(pid, SIGKILL) || waitpid(pid, NULL, 0) != pid) {
		fail("Unable to reap untraced child");
		return 1;
	}
#endif
	unlink(marker);
	unlink(trigger);
	pass();
	return 0;
}
