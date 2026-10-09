/* Target process used by backend-errors.py to test CLONE_UNTRACED detection. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
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

static int cloned_task(void *arg)
{
	(void)arg;
	for (;;)
		pause();
	return 0;
}

int main(int argc, char **argv)
{
	static char stack[65536] __attribute__((aligned(16)));
	const struct timespec delay = { .tv_nsec = 1000000 };
	int flags = CLONE_UNTRACED | SIGCHLD;
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

	pid = clone(cloned_task, stack + sizeof(stack), flags, NULL);
	if (pid <= 0)
		return 1;

	if (write_marker(argv[4], pid))
		return 1;

	for (;;)
		pause();
}
