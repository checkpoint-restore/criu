/* Target process used by backend-errors.py to test a traced fork during dump. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <stdio.h>
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

int main(int argc, char **argv)
{
	const struct timespec delay = { .tv_nsec = 1000000 };
	int pid;

	if (argc != 4)
		return 1;

	if (write_marker(argv[1], (int)getpid()))
		return 1;

	while (access(argv[2], F_OK) != 0)
		nanosleep(&delay, NULL);

	pid = fork();
	if (!pid) {
		for (;;)
			pause();
	}
	if (pid <= 0)
		return 1;

	if (write_marker(argv[3], pid))
		return 1;

	for (;;)
		pause();
}
