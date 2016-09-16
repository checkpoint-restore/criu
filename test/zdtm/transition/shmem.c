#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_author	= "Andrei Vagin <avagin@virtuozzo.com>";

#define MEM_SIZE (1<<25)

int main(int argc, char **argv)
{
	pid_t pid;
	void *addr;
	int *sum, status;
	long size;

	test_init(argc, argv);

	sum = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (sum == MAP_FAILED)
		return 1;
	addr = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (addr == MAP_FAILED)
		return 1;

	pid = fork();
	if (pid < 0)
		return 1;

	if (pid == 0) {
		int i = 0;
		long size = PAGE_SIZE, old_size = MEM_SIZE;

		status = 0;
		while (test_go()) {
			addr = mremap(addr, old_size, size, MREMAP_MAYMOVE);

			status -= *((int *)(addr + size - PAGE_SIZE));

			*((int *)(addr + size - PAGE_SIZE)) = i++;

			status += *((int *)(addr + size - PAGE_SIZE));

			old_size = size;
			size += PAGE_SIZE;
			if (size > MEM_SIZE)
				size = PAGE_SIZE;
		}
		*sum = status;
		return 0;
	}

	test_daemon();
	test_waitsig();

	kill(pid, SIGTERM);
	status = -1;
	waitpid(pid, &status, 0);
	if (status) {
		pr_perror("The child return non-zero code: %d\n", status);
		return 1;
	}

	status = 0;
	for (size = PAGE_SIZE; size <= MEM_SIZE; size += PAGE_SIZE) {
		status += *((int *)(addr + size - PAGE_SIZE));
	}

	if (status != *sum) {
		fail("checksum mismatch: %x %x\n", status, *sum);
		return 1;
	}

	pass();

	return 0;
}
