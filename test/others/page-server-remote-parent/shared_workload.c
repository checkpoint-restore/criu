#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

/* The controller retains expected bytes outside this checkpointed tree. */
int main(int argc, char **argv)
{
	const size_t private_size = 16UL << 20;
	size_t page_size = sysconf(_SC_PAGESIZE);
	size_t shared_size = 32 * page_size;
	unsigned char *private, *shared;
	pid_t child;
	FILE *manifest;

	if (argc != 2)
		return 2;
	if (!getenv("CRIU_TEST_THP") && prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0))
		return 1;
	private = mmap(NULL, private_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	shared = mmap(NULL, shared_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (private == MAP_FAILED || shared == MAP_FAILED)
		return 1;
	if (getenv("CRIU_TEST_THP"))
		madvise(private, private_size, MADV_HUGEPAGE);
	memset(private, 0x29, private_size);
	memset(shared, 0x19, shared_size);
	if (getenv("CRIU_TEST_THP")) {
		/* Optional synchronous collapse; smaps, not this return value, is the oracle. */
		madvise(private, private_size, 25 /* MADV_COLLAPSE */);
	}
	child = fork();
	if (child < 0)
		return 1;
	if (!child) {
		for (;;)
			pause();
	}
	manifest = fopen(argv[1], "w");
	if (!manifest) {
		kill(child, SIGKILL);
		return 1;
	}
	fprintf(manifest, "%d %d %lu %lu %zu %zu %zu\n", getpid(), child,
		(unsigned long)private, (unsigned long)shared, private_size, shared_size, page_size);
	if (fclose(manifest)) {
		kill(child, SIGKILL);
		return 1;
	}
	for (;;)
		pause();
}
