/*
 * Test program that allocates anonymous memory, then forks.
 * The parent and child share COW pages, which forces CRIU to
 * premap private VMAs during restore (exercising process_async_reads()).
 */
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#define MEM_SIZE (5 * 1024 * 1024)

int main(void)
{
	char *p;
	int i;
	pid_t child;

	p = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return 1;

	/* Touch every page so they get dumped */
	for (i = 0; i < MEM_SIZE; i += 4096)
		p[i] = 'X';

	child = fork();
	if (child < 0)
		return 1;

	if (child == 0) {
		/* Child: touch a few pages to create COW divergence */
		for (i = 0; i < MEM_SIZE / 2; i += 4096)
			p[i] = 'Y';
		while (1)
			pause();
		return 0;
	}

	/* Parent: wait forever */
	while (1)
		pause();

	return 0;
}
