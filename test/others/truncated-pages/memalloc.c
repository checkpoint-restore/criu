/*
 * Minimal test program that allocates and fills anonymous memory.
 * Used by truncated-pages tests to produce a large pages file.
 */
#include <sys/mman.h>
#include <unistd.h>

#define MEM_SIZE (5 * 1024 * 1024)

int main(void)
{
	char *p;
	int i;

	p = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return 1;

	for (i = 0; i < MEM_SIZE; i += 4096)
		p[i] = 'X';

	while (1)
		pause();

	return 0;
}
