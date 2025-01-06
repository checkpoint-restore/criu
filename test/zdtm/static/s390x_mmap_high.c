#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "zdtmtst.h"

#define TASK_SIZE_LEVEL_4 0x20000000000000UL /* 8 PB */
#define MAP_SIZE	  0x1000
#define VAL		  0x77

const char *test_doc = "Verify that tasks > 4TB can be checkpointed";
const char *test_author = "Michael Holzheu <holzheu@linux.vnet.ibm.com>";

/*
 * Map memory at the very end of the 8 PB address space
 */
int main(int argc, char **argv)
{
	void *addr = (void *)TASK_SIZE_LEVEL_4 - MAP_SIZE;
	char *buf;
	int i;

	test_init(argc, argv);

	/*
	 * Skip test if kernel does not have the following fix:
	 *
	 * ee71d16d22 ("s390/mm: make TASK_SIZE independent from the number
	 *              of page table levels")
	 */
	if (munmap(addr, MAP_SIZE) == -1) {
		test_daemon();
		test_waitsig();
		skip("Detected kernel without 4 level TASK_SIZE fix");
		pass();
		return 0;
	}

	/* Map memory at the very end of the 8 PB address space */
	buf = mmap(addr, MAP_SIZE, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (buf == MAP_FAILED) {
		pr_perror("Could not create mapping");
		exit(1);
	}
	/* Initialize buffer with data */
	memset(buf, VAL, MAP_SIZE);

	test_daemon();
	test_waitsig();

	/* Verify that we restored the data correctly */
	for (i = 0; i < MAP_SIZE; i++) {
		if (buf[i] == VAL)
			continue;
		fail("%d: %d != %d", i, buf[i], VAL);
		goto out;
	}
	pass();
out:
	return 0;
}
